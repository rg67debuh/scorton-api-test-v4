#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from rich.logging import RichHandler  # type: ignore

    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

import dns.resolver  # type: ignore

MODULE_NAME = "dns_enum"


def query_record(domain: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
        return [str(r.to_text()) for r in answers] if answers.rrset else []
    except Exception as exc:
        logging.info("No %s record found: %s", rtype, exc)
        return []


def dnssec_enabled(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False


def perform_dns_enum(domain: str) -> Dict[str, Any]:
    return {
        "A": query_record(domain, "A"),
        "AAAA": query_record(domain, "AAAA"),
        "MX": query_record(domain, "MX"),
        "NS": query_record(domain, "NS"),
        "TXT": query_record(domain, "TXT"),
        "CAA": query_record(domain, "CAA"),
        "SOA": query_record(domain, "SOA"),
        "dnssec_enabled": dnssec_enabled(domain),
    }


def build_result(target: str) -> Dict[str, Any]:
    result = {
        "module": MODULE_NAME,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "data": {},
    }
    try:
        result["data"] = perform_dns_enum(target)
    except dns.resolver.NXDOMAIN:
        logging.error("Domain does not exist")
        result["status"] = "error"
        result["data"] = {"message": "NXDOMAIN"}
    except Exception as exc:
        logging.error("DNS enumeration failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
    
    if target is None:
        parser = argparse.ArgumentParser(description="Enumerate DNS records")
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
