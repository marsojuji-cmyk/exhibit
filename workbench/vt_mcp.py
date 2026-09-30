#!/usr/bin/env python3
"""Minimal VirusTotal MCP client (Streamable HTTP), stdlib-only.

Endpoint: https://ai.virustotal.com/mcp
Auth: VTAI Agent Token via `x-apikey` header (same token works for REST).

Usage:
    VT_TOKEN=<token> python3 vt_mcp.py tools
    VT_TOKEN=<token> python3 vt_mcp.py call get_domain_report '{"domain":"virustotal.com"}'

The token never appears in logs; pass it via env only.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
from dynamic_credentials import add_surrogate_to_request

ENDPOINT = "https://ai.virustotal.com/mcp"
PROTOCOL_VERSION = "2025-06-18"
CREDENTIAL = "custom.virustotal"
ALLOWED_HOSTS = ["ai.virustotal.com", "www.virustotal.com"]


def _post(payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.add_header("MCP-Protocol-Version", PROTOCOL_VERSION)
    # Vault surrogate -> authd exchanges it for the real Agent Token and
    # places it in the X-Apikey header per the connector's placement.
    # The raw token never touches env, logs, or disk here.
    add_surrogate_to_request(req, CREDENTIAL, allowed_hosts=ALLOWED_HOSTS)
    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code}: {exc.read().decode()[:300]}")
    raw = resp.read().decode()
    # Server may answer plain JSON or an SSE stream; handle both.
    if raw.lstrip().startswith("{"):
        return json.loads(raw)
    data = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            try:
                data = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
    if data is None:
        raise SystemExit(f"unparseable response: {raw[:300]}")
    return data


def _rpc(method, params, rpc_id):
    res = _post({"jsonrpc": "2.0", "id": rpc_id, "method": method,
                 "params": params})
    if "error" in res:
        raise SystemExit(f"RPC error: {res['error']}")
    return res.get("result")


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "tools"
    _rpc("initialize", {"protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "exhibit", "version": "0.1"}},
         1)
    if action == "tools":
        result = _rpc("tools/list", {}, 2)
        for t in result.get("tools", []):
            print(f"- {t['name']}: {t.get('description', '')[:100]}")
    elif action == "call":
        name, args = sys.argv[2], json.loads(sys.argv[3])
        result = _rpc("tools/call", {"name": name, "arguments": args}, 2)
        print(json.dumps(result, indent=2)[:4000])
    else:
        raise SystemExit("unknown action: tools | call")


if __name__ == "__main__":
    main()
