from __future__ import annotations
import argparse
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from rich.logging import RichHandler
    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

import requests

MODULE_NAME = "cookie_scan"


def parse_cookies(headers: List[str]) -> List[Dict[str, Any]]:
    cookies = []
    for header in headers:
        attrs = header.split(";")
        if not attrs:
            continue
        name_val = attrs[0].split("=", 1)
        name = name_val[0].strip()
        val = name_val[1].strip() if len(name_val) > 1 else ""
        info = {"name": name, "value": val, "secure": False, "http_only": False}
        for attr in attrs[1:]:
            item = attr.strip().lower()
            if item == "secure":
                info["secure"] = True
            elif item == "httponly":
                info["http_only"] = True
        cookies.append(info)
    return cookies


def analyze(url: str) -> Dict[str, Any]:
    resp = requests.get(url, timeout=10)
    header_values = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else resp.raw.headers.get_all("Set-Cookie") if resp.raw and hasattr(resp.raw.headers, "get_all") else []
    return {"cookies": parse_cookies(header_values)}


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = analyze(target)
    except Exception as exc:
        logging.error("cookie scan failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
    if target is None:
        parser = argparse.ArgumentParser(description="Inspect cookie security flags")
        parser.add_argument("target", help="URL to check")
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
