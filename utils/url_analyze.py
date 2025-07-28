#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from rich.logging import RichHandler  # type: ignore

    logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
except Exception:
    logging.basicConfig(level=logging.INFO)

import requests  # type: ignore

MODULE_NAME = "url_analyze"


IP_RE = re.compile(r"^(https?://)?(\d{1,3}\.){3}\d{1,3}")


def count_redirects(url: str) -> int:
    redirect_count = 0
    current = url
    session = requests.Session()
    while True:
        resp = session.get(current, allow_redirects=False, timeout=10)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            redirect_count += 1
            current = resp.headers.get("Location")
            if not current:
                break
        else:
            break
    return redirect_count


def check_safe_browsing(url: str) -> str:
    api_key = os.getenv("GOOGLE_SB_API_KEY")
    if not api_key:
        logging.warning("Safe Browsing API key not provided")
        return "unverified"

    payload = {
        "client": {"clientId": "scorton", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=10,
        )
        if resp.status_code == 200 and resp.json().get("matches"):
            return "malicious"
        return "clean"
    except Exception as exc:
        logging.error("Safe Browsing check failed: %s", exc)
        return "unverified"


def analyze_url(url: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "url_length": len(url),
        "contains_ip": bool(IP_RE.match(url)),
        "idn": any(ord(ch) > 127 for ch in url),
    }
    try:
        data["nb_redirections"] = count_redirects(url)
    except Exception as exc:
        logging.error("Redirection check failed: %s", exc)
        data["nb_redirections"] = -1
    data["safe_browsing"] = check_safe_browsing(url)
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
        result["data"] = analyze_url(target)
    except Exception as exc:
        logging.error("URL analysis failed: %s", exc)
        result["status"] = "error"
        result["data"] = {"message": str(exc)}
    return result


def main(target: Optional[str] = None, json_out: Optional[str] = None, api: Optional[bool] = False) -> int:
        
    if target is None:
        parser = argparse.ArgumentParser(description="Analyze a URL")
        parser.add_argument("target", help="URL to analyze")
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
