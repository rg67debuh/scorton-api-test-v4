#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from rich.logging import RichHandler  # type: ignore

    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:  # Rich is optional
    logging.basicConfig(level=logging.INFO)

import whois  # type: ignore


MODULE_NAME = "whois_scan"


def _to_iso(value: Any) -> str | None:
    """Convert datetime or list of datetimes to ISO format."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if value:
        try:
            dt = datetime.fromisoformat(str(value))
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            return str(value)
    return None


def perform_whois(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup for the domain."""
    w = whois.whois(domain)
    data = {
        "domain_name": w.domain_name,
        "registrar": w.registrar,
        "creation_date": _to_iso(w.creation_date),
        "expiration_date": _to_iso(w.expiration_date),
        "organization": getattr(w, "org", None) or getattr(w, "organization", None),
        "country": w.country,
        "name_servers": w.name_servers,
    }
    return data


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = perform_whois(target)
    except Exception as exc:
        logging.error("WHOIS lookup failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:

    if target is None:
        parser = argparse.ArgumentParser(description="Perform WHOIS lookup")
        parser.add_argument("target", help="Domain to query")
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
