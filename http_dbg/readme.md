# HTTP Watch

**HTTP Watch** runs a shell command through a temporary, loopback-only HTTP(S) inspection proxy. It prints each completed request/response exchange in a readable terminal layout and writes a Markdown capture file. Optionally, it writes a structured JSON Lines (`.jsonl`) sidecar too.

It is a small Python wrapper around [mitmproxy](https://docs.mitmproxy.org/stable/). It is not a packet sniffer and cannot guarantee capture of traffic from every application.

## Install

Requirements: Linux or macOS, Python 3.10+, Bash, and `mitmdump` from mitmproxy.

A straightforward install is with `pipx`:

```bash
pipx install mitmproxy
```

Make sure the directory where `pipx` installs applications is on your `PATH`, then install the script somewhere on your `PATH`, for example:

```bash
mkdir -p ~/.local/bin
install -m 755 httpwatch.py ~/.local/bin/httpwatch
```

If `~/.local/bin` is not already on your `PATH`, add it to your shell startup file. Alternatively, run the script directly with `python3 /path/to/httpwatch.py`.

## Usage

Pass the shell command after `--`. For simple commands, you may pass tokens normally:

```bash
httpwatch -- curl -sS https://httpbin.org/json
```

**Quote the entire command** when it includes shell syntax such as a pipeline, redirection, variable expansion, or multiple commands. This ensures the outer shell does not run those operations before HTTP Watch starts:

```bash
httpwatch -- 'curl -sS https://httpbin.org/json | jq .'
httpwatch -- 'curl -i https://example.com > response.txt'
httpwatch -- 'python my_client.py && echo finished'
```

By default, a file such as `httpwatch-20261024-221600.md` is created in the current directory. The terminal shows the captured exchanges, and the final lines report the command's exit code and log path.

### Useful options

```bash
httpwatch --log ./captures/example.md -- 'curl -i https://example.com'
httpwatch --jsonl -- 'python my_client.py'
httpwatch --no-body -- 'python my_client.py'
httpwatch --max-body 4096 -- 'curl https://example.com'
httpwatch --no-color -- 'curl -i https://example.com'
```

- `--log PATH`: choose the Markdown log path. Existing files are not overwritten.
- `--jsonl`: also create a `.jsonl` file with one structured record per exchange.
- `--no-body`: record methods, URLs, status, timing, and headers, but omit bodies.
- `--max-body BYTES`: cap each displayed text body; default is 65,536 bytes per request or response.
- `--no-redact`: disable common secret redaction. Use with care.
- `--record-command`: save the original command in the log. Off by default because command lines sometimes contain credentials.
- `--no-color`: disable terminal colors.

## HTTPS and certificate handling

For HTTPS inspection, the proxy must terminate TLS using a certificate signed by its local mitmproxy CA. HTTP Watch waits for mitmproxy to create its CA, then creates a temporary combined CA bundle and sets common environment variables for the child command. This lets many standard clients—including `curl`, Python `requests`/`urllib`/`httpx`, Node.js, and Git—trust both ordinary system roots and the inspection CA without installing the CA system-wide. The generated bundle is deleted at the end of the run. Mitmproxy's own CA data is kept in `~/.mitmproxy` by default.

Some applications use custom trust stores, certificate pinning, a hard-coded CA bundle, or their own networking stack; those may reject interception or bypass the proxy. Java applications and applications that ignore proxy environment variables may need client-specific configuration. Do not disable upstream TLS verification to work around these failures.

## What it captures—and what it cannot

HTTP Watch sets `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` for the command and runs a local proxy bound only to `127.0.0.1`. It captures HTTP/HTTPS traffic from clients that honor those environment variables. It does not capture arbitrary TCP/UDP traffic, traffic that bypasses the proxy, most QUIC/HTTP/3 traffic that ignores proxy settings, or traffic protected by certificate pinning. Proxy-bypassing clients may need their own proxy flag/configuration. Local and remote behavior should be verified for your particular command.

Responses are logged once received. Failed requests that reach the proxy and produce a flow error are also logged. Non-HTTP binary bodies are summarized rather than dumped as unreadable bytes.

## Privacy and safety

Logs may contain private data. Files are created with owner-only permissions where the operating system supports Unix file modes. By default the tool redacts common sensitive headers (such as `Authorization`, cookies and API-key headers), sensitive-looking URL query parameter names, and matching fields in JSON and URL-encoded form bodies. This is **best-effort redaction, not a guarantee**: secrets embedded in arbitrary text bodies, custom header names, URL paths, compressed/unusual payloads, or application-specific formats may remain. Review the log before sharing it. Use `--no-body` for metadata-only captures when body contents are not necessary.

Do not run commands against systems or accounts you are not authorized to inspect. A proxy certificate authority can decrypt traffic from clients that trust it; protect the files under `~/.mitmproxy` and do not distribute the private CA key (`mitmproxy-ca.pem`).

## Troubleshooting

- **`mitmdump was not found`**: install mitmproxy with `pipx install mitmproxy`, then confirm `command -v mitmdump` works in the same terminal.
- **HTTPS certificate errors**: check whether the client honors the common CA environment variables. A client using certificate pinning or a custom trust store may not be interceptable this way.
- **No exchanges are shown**: confirm the program uses HTTP/HTTPS and respects proxy environment variables. Some tools need a command-line proxy option of their own.
- **An existing log path is rejected**: choose a new path with `--log` so an earlier capture is not silently overwritten.

## Testing

The script uses only the Python standard library itself; mitmproxy is an external executable that supplies the actual proxy. Basic script syntax and CLI parsing can be checked without installing mitmproxy:

```bash
python3 -m py_compile httpwatch.py
python3 httpwatch.py --help
```

A live integration test requires `mitmdump` and working network access. For example:

```bash
httpwatch -- 'curl -sS https://httpbin.org/json'
```
