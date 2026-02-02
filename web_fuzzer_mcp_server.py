# web_fuzzer_mcp_server.py
import asyncio
import os
import re
import csv
import httpx
from typing import Optional, List
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP(name="web_fuzzer_AI")

RESULTS = []

DEFAULT_WORDLIST = ["admin", "login", "config", "api", "secret", "backup"]
JUICY_ENDPOINTS = ["admin", "debug", "swagger", "config", "backup", "phpmyadmin"]
REGEX_RULES = {
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Private Key": r"-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----"
}

INTERESTING_CODES = {200, 301, 302, 401, 403}
NOISY_CODES = {404, 405, 406, 500}
JUICY_KEYWORDS = ["login", "administrator", "dashboard", "control panel"]

async def fetch_url(client, url: str):
    findings = []
    try:
        r = await client.get(url, timeout=5.0)
        text = r.text[:2000].lower()

        # Regex scanning
        for name, pattern in REGEX_RULES.items():
            if re.search(pattern, text):
                findings.append(f"Regex hit: {name}")

        # Juicy endpoint detection (smarter)
        if any(j in url.lower() for j in JUICY_ENDPOINTS):
            if r.status_code in INTERESTING_CODES:
                findings.append("Juicy endpoint detected")
            elif any(kw in text for kw in JUICY_KEYWORDS):
                findings.append("Juicy keyword in response")

        return {
            "url": url,
            "status_code": r.status_code,
            "length": len(r.content),
            "findings": findings
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

@mcp.tool()
async def fuzz_endpoint(base_url: str, paths: Optional[List[str]] = None):
    """Fuzz directories or API endpoints with a wordlist."""
    global RESULTS
    if not base_url.startswith("http"):
        base_url = "http://" + base_url
    paths = paths or DEFAULT_WORDLIST
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [fetch_url(client, f"{base_url.rstrip('/')}/{p}") for p in paths]
        RESULTS = await asyncio.gather(*tasks)
    return RESULTS

@mcp.tool()
async def scan_acl(url: str, cookie: Optional[str] = None):
    """Check ACL flaws by comparing auth vs unauth access."""
    headers = {"Cookie": cookie} if cookie else {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            auth = await client.get(url, headers=headers)
            anon = await client.get(url)
            flaw = (anon.status_code == 200 and auth.status_code == 200)
            return {"url": url, "unauth_status": anon.status_code, "auth_status": auth.status_code, "acl_flaw": flaw}
        except Exception as e:
            return {"url": url, "error": str(e)}

@mcp.tool()
async def regex_scan(url: str, patterns: Optional[List[str]] = None):
    """Scan a URL for sensitive regex-based findings."""
    findings = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            r = await client.get(url, timeout=5.0)
            text = r.text[:2000]
            for name, pattern in REGEX_RULES.items():
                if re.search(pattern, text):
                    findings.append(f"Regex hit: {name}")
            if patterns:
                for p in patterns:
                    if re.search(p, text):
                        findings.append(f"Custom regex hit: {p}")
            return {"url": url, "status_code": r.status_code, "findings": findings}
        except Exception as e:
            return {"url": url, "error": str(e)}

@mcp.tool()
async def export_results(format: str = "json"):
    """Export last fuzz results in various formats."""
    if not RESULTS:
        return {"error": "No results available for export."}
    if format == "json":
        return RESULTS
    if format == "csv":
        filename = "results.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "status_code", "length", "findings"])
            writer.writeheader()
            writer.writerows(RESULTS)
        return {"file": filename}
    if format == "md":
        filename = "results.md"
        with open(filename, "w") as f:
            f.write("# Scan Results\n\n")
            for r in RESULTS:
                f.write(f"- **{r['url']}** → {r.get('status_code')} ({r.get('length')} bytes)\n")
                if r.get("findings"):
                    f.write(f"  - Findings: {', '.join(r['findings'])}\n")
        return {"file": filename}
    return {"error": f"Unsupported format: {format}"}

if __name__ == "__main__":
    mcp.run(transport="stdio")
