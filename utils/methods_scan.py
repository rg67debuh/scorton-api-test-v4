from __future__ import annotations
import argparse
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from rich.logging import RichHandler  # type: ignore
    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

import requests  # type: ignore

MODULE_NAME = "methods_scan"


def check_methods(url: str) -> Dict[str, Any]:
    resp = requests.options(url, timeout=10)
    allowed = resp.headers.get("Allow", "")
    return {"allowed_methods": [m.strip() for m in allowed.split(',') if m.strip()]}


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = check_methods(target)
    except Exception as exc:
        logging.error("HTTP methods check failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
    if target is None:
        parser = argparse.ArgumentParser(description="Check allowed HTTP methods")
        parser.add_argument("target", help="URL to query")
        parser.add_argument("--json-out", dest="json_out", help="Write JSON output to file")
        args = parser.parse_args()
        target = args.target
        json_out = args.json_out
    if not target:
        return 1
    output = build_result(target)
    json_str = json.dumps(output, indent=2)
    status = 0 if output["status"] == "ok" else 1
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(json_str)
    if api is False:
        print(json_str)
        return status
    return status, output


if __name__ == "__main__":
    raise SystemExit(main())
