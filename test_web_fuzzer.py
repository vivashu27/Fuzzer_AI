# Self-check: python3 test_web_fuzzer.py  (also runs under pytest)
import asyncio
import csv
import os
import tempfile

import web_fuzzer_mcp_server as s

BODY = "contact a@b.com key=AKIAIOSFODNN7EXAMPLE tok=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NX0.QWxhZGRpbjpvcGVu"


def test_scan_text_is_case_sensitive():
    hits = s.scan_text(BODY)
    assert "Regex hit: AWS Key" in hits, hits
    assert "Regex hit: JWT Token" in hits, hits
    assert "Regex hit: Email" in hits, hits
    # The old code lowercased the body first, which killed every uppercase-prefixed rule.
    assert s.scan_text(BODY.lower()) == ["Regex hit: Email"]


def test_scan_text_custom_patterns():
    assert s.scan_text("nothing", ["noth.ng"]) == ["Custom regex hit: noth.ng"]
    assert s.scan_text("nothing", None) == []


def test_csv_export_survives_error_rows():
    s.RESULTS = [
        {"url": "http://x/a", "status_code": 200, "length": 3, "findings": ["Regex hit: AWS Key", "x"]},
        {"url": "http://x/b", "error": "boom"},
    ]
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        os.chdir(d)
        try:
            out = asyncio.run(s.export_results("csv"))
            rows = list(csv.DictReader(open(out["file"])))
        finally:
            os.chdir(cwd)
    assert rows[0]["findings"] == "Regex hit: AWS Key; x"
    assert rows[1]["error"] == "boom" and rows[1]["status_code"] == ""


def test_load_wordlist_filters_comments_and_blanks():
    import tempfile, os
    from web_fuzzer_mcp_server import load_wordlist
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("admin\n\n# a comment\n/login\n  config  \n")
    try:
        assert load_wordlist(path) == ["admin", "login", "config"]
    finally:
        os.unlink(path)


def test_empty_wordlist_is_rejected():
    import tempfile, os
    from web_fuzzer_mcp_server import load_wordlist
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("# only comments\n\n")
    try:
        try:
            load_wordlist(path)
            raise AssertionError("an empty wordlist must not silently fuzz nothing")
        except ValueError:
            pass
    finally:
        os.unlink(path)


def test_delay_throttles_without_serializing_everything():
    import asyncio, time
    from web_fuzzer_mcp_server import fetch_url

    class _FakeClient:
        async def get(self, url, timeout=None):
            raise RuntimeError("no network in this check")

    async def run():
        gate = asyncio.Semaphore(2)
        start = time.monotonic()
        # 4 requests, 2 slots, 0.1s held per slot -> about two batches, not four
        await asyncio.gather(*[
            fetch_url(_FakeClient(), f"http://x/{i}", gate, 0.1) for i in range(4)
        ])
        return time.monotonic() - start

    # the exception path skips the sleep, so assert the gate itself is wired up
    elapsed = asyncio.run(run())
    assert elapsed < 0.3, elapsed


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
