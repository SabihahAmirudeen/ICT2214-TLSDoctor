import json
import subprocess
from pathlib import Path
from typing import Any


def run_testssl(target_host: str, testssl_script: Path, out_json: Path) -> Any:
    """
    Run testssl.sh (WSL/Linux) and return parsed JSON output.
    """
    out_json.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(testssl_script),
        "--quiet",
        "--jsonfile",
        str(out_json),
        target_host,
    ]

    if out_json.exists():
        out_json.unlink()  # Remove old output

    subprocess.run(cmd, check=True)

    with out_json.open("r", encoding="utf-8") as f:
        return json.load(f)
