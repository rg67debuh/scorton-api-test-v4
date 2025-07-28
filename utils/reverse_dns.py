from __future__ import annotations
import argparse
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from rich.logging import RichHandler
    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

MODULE_NAME = "reverse_dns"


def perform_lookup(addr: str) -> Dict[str, Any]:
    host, _, _ = socket.gethostbyaddr(addr)
    return {"host": host}


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = perform_lookup(target)
    except Exception as exc:
        logging.error("reverse dns failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
    if target is None:
        parser = argparse.ArgumentParser(description="reverse dns lookup")
        parser.add_argument("target", help="ip to query")
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
