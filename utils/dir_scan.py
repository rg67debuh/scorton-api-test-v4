from __future__ import annotations
import argparse
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from rich.logging import RichHandler
    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

MODULE_NAME = "dir_scan"
DEFAULT_WORDLIST = ["admin", "backup", "config", ".git", "login", "old", "test"]


def scan_dirs(url: str, wordlist: List[str] | None = None) -> Dict[str, int]:
    found: Dict[str, int] = {}
    for path in wordlist or DEFAULT_WORDLIST:
        target = f"{url.rstrip('/')}/{path}"
        try:
            resp = requests.head(target, allow_redirects=False, timeout=5)
            if resp.status_code < 400:
                found[path] = resp.status_code
        except Exception as exc:
            logging.info("request failed: %s", exc)
    return found


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = {"paths": scan_dirs(target)}
    except Exception as exc:
        logging.error("directory scan failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
    if target is None:
        parser = argparse.ArgumentParser(description="discover common directories")
        parser.add_argument("target", help="base URL to scan")
        parser.add_argument("--json-out", dest="json_out", help="write JSON output to file")
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
