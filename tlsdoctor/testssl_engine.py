import json
import subprocess
from pathlib import Path
from typing import Any


def run_testssl(target_host: str, testssl_script: Path, out_json: Path) -> Any:
    """
    Run testssl.sh (WSL/Linux) and return parsed JSON output.
    Provides detailed stdout/stderr if execution fails.
    """
    out_json.parent.mkdir(parents=True, exist_ok=True)

    if out_json.exists():
        out_json.unlink()  # Remove old output

    script_dir = testssl_script.parent

    cmd = [
        "bash",
        str(testssl_script),
        "--quiet",
        "--jsonfile",
        str(out_json),
        target_host,
    ]

    result = subprocess.run(
        cmd,
        cwd=str(script_dir),
        text=True,
        capture_output=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"testssl.sh failed (rc={result.returncode}).\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}\n"
            f"Script: {testssl_script}"
        )

    if not out_json.exists():
        raise RuntimeError(
            "testssl.sh reported success but JSON output file was not created. "
            f"Expected: {out_json}"
        )

    with out_json.open("r", encoding="utf-8") as f:
        return json.load(f)
