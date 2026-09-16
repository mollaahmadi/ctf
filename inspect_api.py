#!/usr/bin/env python3
"""Inspect one HTTP response. Python 3.10+, standard library only.

Usage: python3 inspect_api.py [URL] [--output report.json]
This is a response diagnostic, not proof that an application is secure.
"""
import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "https://691f0f0d-991d-49ef-91fc-68eadee79a95.n3.bluctf.ir/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def analyze(status, headers, body, truncated=False):
    headers = {k.lower(): v for k, v in headers.items()}
    findings = []

    def add(level, kind, detail):
        findings.append({"level": level, "kind": kind, "detail": detail})

    if status >= 500:
        add("warning", "server_error", f"Server returned HTTP {status}.")
    elif status >= 400:
        add("warning", "client_error", f"HTTP {status}; endpoint, authorization or request may be incorrect.")
    elif 300 <= status < 400:
        add("info", "redirect", "Redirect was not followed. Inspect the Location header.")
    if truncated:
        add("warning", "truncated", "Response exceeds the byte limit; analysis is partial.")
    if not body:
        add("info", "empty_body", "Response body is empty (can be valid, e.g. HTTP 204).")

    content_type = headers.get("content-type", "")
    charset = re.search(r"charset\s*=\s*[\"']?([\w-]+)", content_type, re.I)
    try:
        text = body.decode(charset.group(1) if charset else "utf-8", errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
        add("info", "unknown_charset", "Unknown declared charset; used UTF-8.")
    parsed = None
    is_json = False
    expects_json = "json" in content_type.lower()
    if body and not truncated and (expects_json or text.lstrip().startswith(("{", "["))):
        try:
            parsed = json.loads(text)
            is_json = True
        except ValueError:
            add("warning" if expects_json else "info", "invalid_json", "Body could not be parsed as JSON.")
    if isinstance(parsed, dict):
        if parsed == {"status": "ok"}:
            add("info", "health_check", "This looks like a health-check response. It does not test catalogue/search behavior or establish security.")
        for key in ("error", "errors", "exception"):
            if parsed.get(key):
                add("warning", "application_error", f"Nonempty top-level '{key}' field; inspect its meaning.")
    patterns = {
        "debug_trace": r"Traceback \(most recent call last\)|werkzeug\.debug|SQLSTATE\[|Fatal error:| at \S+\([^\n]*\.java:\d+\)",
        "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "ctf_flag": r"\bBDD\{[^}\r\n]{1,256}\}",
    }
    for kind, pattern in patterns.items():
        if re.search(pattern, text):
            add("warning", kind, "Potential information disclosure in response; inspect the body preview.")
    server = headers.get("server", "")
    if re.search(r"/\d", server):
        add("info", "server_banner", "Server header advertises a product/version; this alone is not a vulnerability.")
    if headers.get("access-control-allow-origin") == "*":
        add("info", "public_cors", "Wildcard CORS is allowed; often intentional for public APIs, not by itself a vulnerability.")
    return findings, {"valid_json": is_json, "json_type": type(parsed).__name__ if is_json else None,
                      "body_preview": text[:4096], "preview_truncated": len(text) > 4096}


def inspect(url, timeout=20, max_bytes=1048576):
    target = urllib.parse.urlsplit(url)
    if target.scheme not in ("http", "https") or not target.hostname:
        raise ValueError("Provide a complete http:// or https:// URL")
    if target.username is not None or target.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    request = urllib.request.Request(url, headers={
        "User-Agent": "CTF-Response-Inspector/1.0", "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "identity",
    })
    started = time.monotonic()
    report = {"url": url, "method": "GET", "redirects_followed": False}
    try:
        opener = urllib.request.build_opener(NoRedirect())
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc  # Preserve and analyze error response bodies too.
        with response:
            body = response.read(max_bytes + 1)
            status = response.code
            headers = dict(response.headers.items())
        truncated = len(body) > max_bytes
        body = body[:max_bytes]
        findings, details = analyze(status, headers, body, truncated)
        report.update(status=status, headers=headers, bytes_captured=len(body),
                      truncated=truncated, findings=findings, **details)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        report.update(connection_error=str(exc), findings=[{
            "level": "error", "kind": "connection_error",
            "detail": "Request failed; this does not establish a flaw in the application.",
        }])
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["scope"] = "One GET request; heuristic response analysis only. No endpoint enumeration or exploitation."
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=float, default=20, help="Socket timeout in seconds (not an overall deadline)")
    parser.add_argument("--max-bytes", type=int, default=1048576)
    parser.add_argument("--output", help="Also save JSON report locally (may contain response data)")
    args = parser.parse_args()
    if args.timeout <= 0 or args.max_bytes <= 0:
        parser.error("timeout and max-bytes must be positive")
    try:
        report = inspect(args.url, args.timeout, args.max_bytes)
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, ensure_ascii=True)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    return 2 if "connection_error" in report else int(any(f["level"] == "warning" for f in report["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
