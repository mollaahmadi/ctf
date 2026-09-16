# CTF tools

## HTTP response inspector

`inspect_api.py` makes one GET request and reports HTTP status, response headers, JSON validity, application errors, and potential information disclosure. It defaults to the Ashen Archive challenge URL and uses only the Python standard library (Python 3.10+).

```bash
python3 inspect_api.py
python3 inspect_api.py --output report.json
python3 inspect_api.py https://example.com/api --timeout 20 --max-bytes 1048576
```

TLS verification is enabled. Redirects are reported rather than followed. Response capture is bounded; the timeout applies to socket operations, not the entire request. No endpoint enumeration or exploitation is performed.

Exit codes: `0` for no warning findings, `1` for warning findings, `2` for connection or argument errors. Findings are heuristic and require interpretation; a successful health check does not establish application security. Reports include headers and a body preview and may contain sensitive response data.

The supplied challenge endpoint returned HTTP 200 with `{"status":"ok"}` during validation. This indicates a health-check response, not a test of catalogue/search functionality. The server also advertised `AshenArchive/1.0`; a version banner alone is not a demonstrated vulnerability.
