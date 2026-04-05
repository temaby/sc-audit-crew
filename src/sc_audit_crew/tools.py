"""
CrewAI tools for running external audit instruments.

Each tool is a real subprocess call.
Agents receive structured output, not raw stdout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _venv_bin(name: str) -> str:
    """Return the full path to a binary installed in the same venv as this interpreter.

    Falls back to the bare name (relies on PATH) if the venv-local copy is not found.
    This ensures tools like slither and solc-select work even when the venv is not
    activated in the calling shell's environment.
    """
    scripts_dir = Path(sys.executable).parent
    for candidate_name in (f"{name}.exe", name):
        candidate = scripts_dir / candidate_name
        if candidate.exists():
            return str(candidate)
    return name  # fallback


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> tuple[str, str, int]:
    """Run a subprocess; returns (stdout, stderr, returncode)."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,  # prevent interactive prompts (e.g. solc-select on Windows CI)
        cwd=cwd,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def _detect_solc_version(source: str) -> str | None:
    """Return the highest concrete version found across all pragma solidity statements."""
    versions = re.findall(r"pragma solidity\s+[^;]*?(\d+\.\d+\.\d+)", source)
    if not versions:
        return None
    return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def _setup_solc(version: str) -> str | None:
    """Install (if needed) and activate a specific solc version via solc-select.

    Returns the absolute path to the solc binary for that version so callers
    can pass it via --solc, avoiding PATH lookup failures in subprocesses.
    Returns None if solc-select is unavailable or the binary cannot be located.
    """
    try:
        _ss = _venv_bin("solc-select")
        stdout, _, code = _run([_ss, "versions"], timeout=10)
        if version not in stdout:
            print(f"  [slither] installing solc {version}...")
            _run([_ss, "install", version], timeout=120)
        _run([_ss, "use", version], timeout=10)
        print(f"  [slither] solc {version} active")
        # Locate the actual solc binary: solc-select stores it at
        # ~/.solc-select/artifacts/solc-{version}/solc-{version}[.exe]
        artifacts_dir = Path.home() / ".solc-select" / "artifacts" / f"solc-{version}"
        for cname in (f"solc-{version}.exe", f"solc-{version}"):
            candidate = artifacts_dir / cname
            if candidate.exists():
                print(f"  [slither] solc binary: {candidate}")
                return str(candidate)
        print(f"  [slither] WARNING: solc binary not found under {artifacts_dir}")
    except FileNotFoundError:
        print("  [slither] solc-select not found, skipping version management")
    except Exception as e:
        print(f"  [slither] solc-select error: {e}")
    return None


def _find_foundry_root(start: Path) -> Path | None:
    """Walk upward from start until a directory containing foundry.toml is found."""
    current = start if start.is_dir() else start.parent
    while True:
        if (current / "foundry.toml").exists():
            return current
        parent = current.parent
        if parent == current:  # filesystem root
            return None
        current = parent


def _try_flatten(sol_file: Path) -> Path | None:
    """Attempt to flatten a .sol file using forge flatten.

    Returns path to a temporary flat file on success, None otherwise.
    Caller is responsible for deleting the temp file.
    """
    # Use the Foundry project root as cwd so forge can locate foundry.toml even when
    # the .sol file is in a deeply nested subdirectory (e.g. src/contracts/Token.sol).
    foundry_root = _find_foundry_root(sol_file)
    cwd = str(foundry_root) if foundry_root else str(sol_file.parent)
    try:
        stdout, stderr, code = _run(
            ["forge", "flatten", str(sol_file)],
            cwd=cwd,
            timeout=60,
        )
        if code == 0 and stdout.strip():
            fd, tmp_path = tempfile.mkstemp(suffix=".flat.sol")
            os.close(fd)
            tmp = Path(tmp_path)
            tmp.write_text(stdout, encoding="utf-8")
            return tmp
    except FileNotFoundError:
        pass  # forge not installed
    except subprocess.TimeoutExpired:
        pass
    return None


def _find_original_sol(original_dir: Path, contract_name: str) -> Path | None:
    """Recursively find {contract_name}.sol in original_dir, skipping flat/test files."""
    for f in sorted(original_dir.rglob(f"{contract_name}.sol")):
        parts_lower = [p.lower() for p in f.parts]
        if any(x in parts_lower for x in ("flat", "flattened", "test", "tests", "mock")):
            continue
        if re.search(r"flat|flattened", f.stem, re.IGNORECASE):
            continue
        return f
    return None


def _compute_offset_map(flat_path: Path, contract_names: list[str], original_dir: Path) -> dict[str, int]:
    """Return {contract_name: offset} where offset = flat_lineno - original_lineno.

    Finds the `contract Name` definition line in both files and computes the delta.
    To convert a flat file line N to the original file line: N - offset.
    """
    flat_lines = flat_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    offsets: dict[str, int] = {}

    for name in contract_names:
        orig_path = _find_original_sol(original_dir, name)
        if orig_path is None:
            continue

        orig_lines = orig_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        pattern = re.compile(
            rf"^\s*(abstract\s+)?(contract|library|interface)\s+{re.escape(name)}\b"
        )

        orig_lineno = next(
            (i for i, line in enumerate(orig_lines, start=1) if pattern.match(line)), None
        )
        flat_lineno = next(
            (i for i, line in enumerate(flat_lines, start=1) if pattern.match(line)), None
        )

        if orig_lineno is not None and flat_lineno is not None:
            offsets[name] = flat_lineno - orig_lineno
            print(f"  [slither] line offset for {name}: {offsets[name]} "
                  f"(flat:{flat_lineno} orig:{orig_lineno})")

    return offsets


# ------------------------------------------------------------------
# Slither Tool
# ------------------------------------------------------------------

class SlitherInput(BaseModel):
    target: str = Field(..., description="Path to .sol file, flat file, or project directory")
    exclude_informational: bool = Field(
        True,
        description=(
            "Exclude Slither informational findings (dead-code, unused-return, etc.). "
            "Default True: informational checks can double/triple finding count and exceed "
            "the static analysis agent's 16K token ceiling. Change to False only when "
            "the SA task token budget is also raised to accommodate the extra volume."
        ),
    )
    contract_names: list[str] = Field(
        default_factory=list,
        description="Project contract names to keep findings for (empty = keep all). "
                    "Used to filter out dependency findings in flat files.",
    )
    original_file_dir: str = Field(
        "",
        description="Project root directory containing the original .sol source files. "
                    "When set and target is a flat file, line numbers in findings are "
                    "remapped from flat file lines to original file lines.",
    )


class SlitherTool(BaseTool):
    name: str = "slither_static_analysis"
    description: str = (
        "Runs Slither — a Solidity static analyzer. "
        "Returns a list of vulnerabilities with severity, location, and description. "
        "Use for initial contract scanning."
    )
    args_schema: Type[BaseModel] = SlitherInput

    def _run(self, target: str, exclude_informational: bool = True,
             contract_names: list[str] | None = None, original_file_dir: str = "") -> str:
        target_path = Path(target).resolve()
        flat_file: Path | None = None
        solc_path: str | None = None

        try:
            # -- Determine slither target and source for pragma detection --
            if target_path.is_dir():
                slither_target = str(target_path)
                # Use first .sol file found for pragma detection
                sol_files = sorted(target_path.rglob("*.sol"))
                source_file = sol_files[0] if sol_files else None
                print(f"  [slither] mode=directory target={target_path}")
            else:
                # Single file — try to flatten first
                # Strip BOM if present (Hardhat flatten adds UTF-8 BOM on Windows)
                raw = target_path.read_bytes()
                if raw[:3] == b"\xef\xbb\xbf":
                    print("  [slither] stripping UTF-8 BOM from flat file")
                    fd, bom_tmp = tempfile.mkstemp(suffix=".sol")
                    os.close(fd)
                    bom_file = Path(bom_tmp)
                    bom_file.write_bytes(raw[3:])
                    flat_file = bom_file  # will be cleaned up in finally
                    slither_target = str(bom_file)
                else:
                    print(f"  [slither] mode=single-file, attempting forge flatten...")
                    flat_file = _try_flatten(target_path)
                    if flat_file:
                        print(f"  [slither] flatten OK → {flat_file}")
                    else:
                        print("  [slither] forge not available, using original file")
                    slither_target = str(flat_file) if flat_file else str(target_path)
                source_file = target_path

            # -- Auto-select solc version --
            if source_file and source_file.exists():
                try:
                    source_text = source_file.read_text(encoding="utf-8", errors="ignore")
                    version = _detect_solc_version(source_text)
                    if version:
                        print(f"  [slither] detected solc {version}, selecting via solc-select...")
                        solc_path = _setup_solc(version)
                except OSError:
                    pass

            # -- Run Slither — write JSON to a temp file (avoids stdout issues on Windows) --
            fd, json_path = tempfile.mkstemp(suffix=".slither.json")
            os.close(fd)
            os.unlink(json_path)  # Slither refuses to overwrite existing files
            try:
                cmd = [_venv_bin("slither"), slither_target, "--json", json_path]
                if exclude_informational:
                    cmd += ["--exclude-informational"]
                if solc_path:
                    cmd += ["--solc", solc_path]

                print(f"  [slither] running: {' '.join(cmd)}")
                try:
                    stdout, stderr, code = _run(cmd, timeout=180)
                except FileNotFoundError:
                    print("  [slither] ERROR: not installed")
                    return json.dumps({
                        "error": "Slither is not installed",
                        "hint": "Run: pip install slither-analyzer",
                    })
                except subprocess.TimeoutExpired:
                    print("  [slither] ERROR: timeout >180s")
                    return json.dumps({"error": "Slither timeout (>180s)"})

                print(f"  [slither] exit_code={code}, stdout={len(stdout)}b, stderr={len(stderr)}b")
                if stderr.strip():
                    print(f"  [slither] stderr:\n{stderr}")

                json_file = Path(json_path)
                size = json_file.stat().st_size if json_file.exists() else -1
                print(f"  [slither] json file: exists={json_file.exists()}, size={size}b")
                if not json_file.exists() or size == 0:
                    return json.dumps({
                        "error": "Slither produced no output",
                        "hint": stderr.strip()[:3000] or "Check that the target path exists and contracts compile",
                        "stdout": stdout.strip()[:1000],
                    })

                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    return json.dumps({
                        "error": f"Failed to parse Slither JSON: {exc}",
                        "hint": "Check solc version compatibility",
                    })
            finally:
                Path(json_path).unlink(missing_ok=True)

            # Replace temp file path with original filename in all text fields
            original_name = target_path.name
            temp_str = str(flat_file) if flat_file else str(target_path)
            temp_fwd = temp_str.replace("\\", "/")

            def _clean(s: str) -> str:
                return s.replace(temp_str, original_name).replace(temp_fwd, original_name)

            # Filtering strategy:
            # - directory mode: no filter (Slither natively excludes lib/node_modules)
            # - file mode: filter by contract_names if provided (removes dependency findings)
            if target_path.is_dir():
                project_names: set[str] = set()  # empty = keep all
            else:
                project_names = set(contract_names) if contract_names else set()

            def _element_contract(el: dict) -> str:
                if el.get("type") == "contract":
                    return el.get("name", "")
                return el.get("type_specific_fields", {}).get("parent", {}).get("name", "")

            def _is_main(detector: dict) -> bool:
                if not project_names:
                    return True  # no filter
                elements = detector.get("elements", [])
                if not elements:
                    return True
                return any(_element_contract(e) in project_names for e in elements)

            # Normalize to internal format
            all_count = 0
            findings = []
            for detector in data.get("results", {}).get("detectors", []):
                all_count += 1
                if not _is_main(detector):
                    continue
                elements = detector.get("elements", [])
                location = ""
                detected_contract = ""
                if elements:
                    el = elements[0]
                    src = el.get("source_mapping", {})
                    lines = src.get("lines", [])
                    filename = _clean(src.get("filename_relative", "?"))
                    location = f"{filename}:{lines[0] if lines else '?'}"
                    detected_contract = _element_contract(el)

                findings.append({
                    "tool": "slither",
                    "check": detector.get("check"),
                    "impact": detector.get("impact"),
                    "confidence": detector.get("confidence"),
                    "description": _clean(detector.get("description", "")),
                    "location": location,
                    "_contract": detected_contract,  # used for line remapping, removed below
                })

            filtered = all_count - len(findings)
            print(f"  [slither] {len(findings)} findings kept, {filtered} filtered (dependencies)")

            # Remap flat file line numbers to original file line numbers
            if original_file_dir and not target_path.is_dir():
                orig_dir = Path(original_file_dir)
                remap_names = list(project_names) if project_names else list(contract_names or [])
                if orig_dir.exists() and remap_names:
                    offset_map = _compute_offset_map(Path(slither_target), remap_names, orig_dir)
                    if offset_map:
                        for f in findings:
                            cname = f.get("_contract", "")
                            offset = offset_map.get(cname)
                            if offset is not None:
                                loc = f.get("location", "")
                                fname, sep, lineno_str = loc.rpartition(":")
                                if sep and lineno_str.isdigit():
                                    original_line = max(1, int(lineno_str) - offset)
                                    f["location"] = f"{cname}.sol:{original_line}"

            # Remove internal field before returning
            for f in findings:
                f.pop("_contract", None)

            return json.dumps({"findings_count": len(findings), "findings": findings}, indent=2)

        finally:
            if flat_file and flat_file.exists():
                flat_file.unlink()


# ------------------------------------------------------------------
# Mythril Tool
# ------------------------------------------------------------------

class MythrilInput(BaseModel):
    contract_path: str = Field(..., description="Path to .sol file")
    max_depth: int = Field(22, description="Symbolic execution depth")
    timeout: int = Field(120, description="Timeout in seconds")


class MythrilTool(BaseTool):
    name: str = "mythril_symbolic_execution"
    description: str = (
        "Runs Mythril (myth analyze) — symbolic execution for EVM bytecode. "
        "Good at finding integer overflows and reentrancy via formal analysis. "
        "Slower than Slither; use to confirm critical findings."
    )
    args_schema: Type[BaseModel] = MythrilInput

    def _run(self, contract_path: str, max_depth: int = 22, timeout: int = 120) -> str:
        cmd = [
            "myth", "analyze", contract_path,
            "--execution-timeout", str(timeout),
            "--max-depth", str(max_depth),
            "-o", "jsonv2",
        ]

        try:
            stdout, stderr, code = _run(cmd, timeout=timeout + 30)
        except FileNotFoundError:
            return json.dumps({"error": "Mythril is not installed. Run: pip install mythril"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": f"Mythril timeout (>{timeout}s)"})

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return json.dumps({"error": "Failed to parse Mythril output", "raw": stdout[:2000]})

        issues = []
        for issue in data:
            issues.append({
                "tool": "mythril",
                "title": issue.get("title"),
                "severity": issue.get("severity"),
                "description": issue.get("description"),
                "function": issue.get("function"),
                "location": f"{issue.get('filename', '?')}:{issue.get('lineno', '?')}",
                "swc_id": issue.get("swcID"),
            })

        return json.dumps({"issues_count": len(issues), "issues": issues}, indent=2)


# ------------------------------------------------------------------
# Foundry Fuzz Tool (Phase 2 — kept for future use)
# ------------------------------------------------------------------

class FoundryFuzzInput(BaseModel):
    test_code: str = Field(..., description="Full Foundry test code (Solidity)")
    project_root: str = Field(..., description="Path to the foundry project")
    test_function: str = Field("testFuzz", description="Test function name to run")
    runs: int = Field(1000, description="Number of fuzz runs")


class FoundryFuzzTool(BaseTool):
    name: str = "foundry_fuzz_test"
    description: str = (
        "Writes and runs a Foundry fuzz test to verify a PoC. "
        "Use to confirm Critical/High findings. "
        "Pass the full Solidity test code and the path to the foundry project."
    )
    args_schema: Type[BaseModel] = FoundryFuzzInput

    def _run(self, test_code: str, project_root: str, test_function: str = "testFuzz", runs: int = 1000) -> str:
        test_dir = Path(project_root) / "test" / "audit"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_dir / "AuditPoC.t.sol"

        test_file.write_text(test_code)

        cmd = [
            "forge", "test",
            "--match-test", test_function,
            "--fuzz-runs", str(runs),
            "-vvv",
        ]

        try:
            stdout, stderr, code = _run(cmd, cwd=project_root, timeout=300)
        except FileNotFoundError:
            return json.dumps({"error": "Foundry is not installed. See: https://getfoundry.sh"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "Foundry timeout (>300s)"})

        return json.dumps({
            "success": code == 0,
            "returncode": code,
            "output": stdout[-3000:],
            "stderr": stderr[-500:] if stderr else "",
            "test_file": str(test_file),
        }, indent=2)


# ------------------------------------------------------------------
# Etherscan Tool (on-chain analysis)
# ------------------------------------------------------------------

class EtherscanInput(BaseModel):
    address: str = Field(..., description="Contract address 0x...")
    network: str = Field("mainnet", description="mainnet | sepolia | polygon | arbitrum | optimism")


class EtherscanTool(BaseTool):
    name: str = "etherscan_contract_lookup"
    description: str = (
        "Fetches on-chain contract info from Etherscan: "
        "verified source, ABI, proxy info, creation tx. "
        "Use for on-chain verification and analysis of already-deployed contracts."
    )
    args_schema: Type[BaseModel] = EtherscanInput

    def _run(self, address: str, network: str = "mainnet") -> str:
        api_key = os.getenv("ETHERSCAN_API_KEY")
        if not api_key:
            return json.dumps({"error": "ETHERSCAN_API_KEY is not set in environment"})

        base_urls = {
            "mainnet": "https://api.etherscan.io/api",
            "goerli": "https://api-goerli.etherscan.io/api",
            "sepolia": "https://api-sepolia.etherscan.io/api",
            "polygon": "https://api.polygonscan.com/api",
            "arbitrum": "https://api.arbiscan.io/api",
            "optimism": "https://api-optimistic.etherscan.io/api",
        }
        base = base_urls.get(network, base_urls["mainnet"])

        params = urllib.parse.urlencode({
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        })

        try:
            with urllib.request.urlopen(f"{base}?{params}", timeout=15) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            return json.dumps({"error": str(e)})

        if data.get("status") != "1":
            return json.dumps({"error": data.get("message", "Etherscan error"), "result": data})

        result = data["result"][0]
        return json.dumps({
            "contract_name": result.get("ContractName"),
            "compiler_version": result.get("CompilerVersion"),
            "is_proxy": result.get("Proxy") == "1",
            "implementation": result.get("Implementation"),
            "license": result.get("LicenseType"),
            "abi": result.get("ABI"),
            # Source code intentionally excluded — can be very large;
            # agent may request it separately if needed
        }, indent=2)


# ------------------------------------------------------------------
# VectorReadTool — loads a security vector procedure file by ID
# ------------------------------------------------------------------

_VECTORS_DIR = Path(__file__).parent / "knowledge" / "vectors"


class _VectorReadInput(BaseModel):
    vector_id: str = Field(
        description='The vector ID to load, e.g. "V07" or "V14". '
                    "Must be one of V01–V19."
    )


class VectorReadTool(BaseTool):
    name: str = "VectorReadTool"
    description: str = (
        "Reads the procedure file for a specific security audit vector. "
        'Input: vector_id as a string like "V07" or "V14". '
        "Returns the full procedure text for that vector. "
        "Always call this before analysing the contract for that vector."
    )
    args_schema: Type[BaseModel] = _VectorReadInput

    def _run(self, vector_id: str) -> str:
        # Accept both "V07" and "07" for convenience
        vid = vector_id.strip().upper()
        if not vid.startswith("V"):
            vid = "V" + vid
        path = _VECTORS_DIR / f"{vid}.md"
        if not path.exists():
            return (
                f"Error: Vector file {vid}.md not found in knowledge/vectors/. "
                f"Valid IDs are V01–V19."
            )
        return path.read_text(encoding="utf-8")
