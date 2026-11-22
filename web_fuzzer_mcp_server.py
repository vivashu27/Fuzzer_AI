# web_fuzzer_mcp_server.py
import asyncio
import csv
import os
import re
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
JUICY_KEYWORDS = ["login", "administrator", "dashboard", "control panel"]

# Secrets normally sit well past the first screen of a bundle; cap only to bound memory.
MAX_SCAN_CHARS = 200_000
# One fuzz run with a big wordlist would otherwise open a socket per path.
MAX_CONCURRENCY = 20
# A wordlist file is one path per line; '#' comments and blanks are dropped.
MAX_WORDLIST_ENTRIES = 50_000


def scan_text(text: str, patterns: Optional[List[str]] = None) -> List[str]:
    """Regex findings for a response body. Case-sensitive: AKIA/AIza/eyJ prefixes are."""
    findings = [f"Regex hit: {name}" for name, p in REGEX_RULES.items() if re.search(p, text)]
    findings += [f"Custom regex hit: {p}" for p in (patterns or []) if re.search(p, text)]
    return findings


def load_wordlist(path: str) -> List[str]:
    """Paths from a wordlist file, ignoring blanks and '#' comments."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        entries = [
            line.strip().lstrip("/")
            for line in f
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not entries:
        raise ValueError(f"Wordlist {path} contains no usable entries.")
    return entries[:MAX_WORDLIST_ENTRIES]


async def fetch_url(client, url: str, gate: Optional[asyncio.Semaphore] = None,
                    delay: float = 0.0):
    try:
        if gate is None:
            r = await client.get(url, timeout=5.0)
        else:
            # Holding the slot across the delay is what bounds the request rate:
            # roughly concurrency/delay requests per second.
            async with gate:
                r = await client.get(url, timeout=5.0)
                if delay:
                    await asyncio.sleep(delay)
    except Exception as e:
        return {"url": url, "error": str(e)}

    text = r.text[:MAX_SCAN_CHARS]
    findings = scan_text(text)

    if any(j in url.lower() for j in JUICY_ENDPOINTS):
        if r.status_code in INTERESTING_CODES:
            findings.append("Juicy endpoint detected")
        elif any(kw in text.lower() for kw in JUICY_KEYWORDS):
            findings.append("Juicy keyword in response")

    return {
        "url": url,
        "status_code": r.status_code,
        "length": len(r.content),
        "findings": findings
    }


@mcp.tool()
async def fuzz_endpoint(
    base_url: str,
    paths: Optional[List[str]] = None,
    wordlist_file: Optional[str] = None,
    concurrency: int = MAX_CONCURRENCY,
    delay: float = 0.0,
    retries: int = 0,
):
    """Fuzz directories or API endpoints with a wordlist.

    Args:
        base_url: Target root, e.g. https://example.com. A missing scheme becomes http://.
        paths: Explicit paths to try. Wins over wordlist_file.
        wordlist_file: Path to a wordlist file, one entry per line ('#' comments ignored).
        concurrency: Maximum simultaneous requests (1-100).
        delay: Seconds to wait after each request before freeing its slot. Combined
            with concurrency this caps the request rate, for targets behind a WAF
            or rate limiter.
        retries: Connection-level retries per request (httpx transport retries).
    """
    global RESULTS
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    if paths is None and wordlist_file:
        try:
            paths = load_wordlist(wordlist_file)
        except (OSError, ValueError) as e:
            return {"error": str(e)}
    paths = paths or DEFAULT_WORDLIST

    concurrency = max(1, min(100, concurrency))
    delay = max(0.0, delay)
    gate = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency)
    transport = httpx.AsyncHTTPTransport(retries=max(0, retries))
    async with httpx.AsyncClient(
        follow_redirects=True, limits=limits, transport=transport
    ) as client:
        tasks = [
            fetch_url(client, f"{base_url.rstrip('/')}/{p}", gate, delay)
            for p in paths
        ]
        RESULTS = await asyncio.gather(*tasks)
    return RESULTS


@mcp.tool()
async def scan_acl(url: str, cookie: Optional[str] = None):
    """Check ACL flaws by comparing authenticated vs anonymous access."""
    if not cookie:
        return {"url": url, "error": "cookie is required, otherwise both requests are anonymous."}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            auth = await client.get(url, headers={"Cookie": cookie})
            anon = await client.get(url)
        except Exception as e:
            return {"url": url, "error": str(e)}

    # Equal-size bodies mean the anonymous request got the protected page, not a login/stub page.
    sizes = (len(auth.content), len(anon.content))
    similar = min(sizes) >= 0.95 * max(max(sizes), 1)
    flaw = anon.status_code == 200 and auth.status_code == 200 and similar
    return {
        "url": url,
        "unauth_status": anon.status_code,
        "auth_status": auth.status_code,
        "unauth_length": len(anon.content),
        "auth_length": len(auth.content),
        "acl_flaw": flaw
    }


@mcp.tool()
async def regex_scan(url: str, patterns: Optional[List[str]] = None):
    """Scan a URL for sensitive regex-based findings."""
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            r = await client.get(url, timeout=5.0)
        except Exception as e:
            return {"url": url, "error": str(e)}
    return {
        "url": url,
        "status_code": r.status_code,
        "findings": scan_text(r.text[:MAX_SCAN_CHARS], patterns)
    }


@mcp.tool()
async def export_results(format: str = "json"):
    """Export last fuzz results in various formats."""
    if not RESULTS:
        return {"error": "No results available for export."}
    if format == "json":
        return RESULTS
    if format == "csv":
        path = os.path.abspath("results.csv")
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["url", "status_code", "length", "findings", "error"],
                restval="",
                extrasaction="ignore",
            )
            writer.writeheader()
            for r in RESULTS:
                writer.writerow({**r, "findings": "; ".join(r.get("findings", []))})
        return {"file": path}
    if format == "md":
        path = os.path.abspath("results.md")
        with open(path, "w") as f:
            f.write("# Scan Results\n\n")
            for r in RESULTS:
                if r.get("error"):
                    f.write(f"- **{r['url']}** -> error: {r['error']}\n")
                    continue
                f.write(f"- **{r['url']}** -> {r.get('status_code')} ({r.get('length')} bytes)\n")
                if r.get("findings"):
                    f.write(f"  - Findings: {', '.join(r['findings'])}\n")
        return {"file": path}
    return {"error": f"Unsupported format: {format}"}


if __name__ == "__main__":
    mcp.run(transport="stdio")
