#!/usr/bin/env python3
"""Run a shell command through a local mitmproxy and log HTTP exchanges."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "1.0.0"

ADDON_SOURCE = r'''from __future__ import annotations
import datetime as dt
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mitmproxy import http

LOG_PATH = os.environ["HTTPWATCH_LOG_PATH"]
JSONL_PATH = os.environ.get("HTTPWATCH_JSONL_PATH", "")
BODY_LIMIT = int(os.environ.get("HTTPWATCH_BODY_LIMIT", "65536"))
SHOW_BODY = os.environ.get("HTTPWATCH_SHOW_BODY", "1") == "1"
REDACT = os.environ.get("HTTPWATCH_REDACT", "1") == "1"
USE_COLOR = os.environ.get("HTTPWATCH_COLOR", "0") == "1"

SENSITIVE = re.compile(
    r"(^|[-_])(authorization|proxy-authorization|cookie|set-cookie|"
    r"api[-_]?key|private[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|"
    r"password|passwd|client[-_]?secret|session|sessionid|credential|signature|sig|auth|jwt)([-_]|$)",
    re.IGNORECASE,
)
SENSITIVE_EXACT = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "key", "signature", "sig", "auth", "jwt"}

C = {
    "reset": "\x1b[0m", "bold": "\x1b[1m", "dim": "\x1b[2m",
    "cyan": "\x1b[36m", "green": "\x1b[32m", "yellow": "\x1b[33m",
    "red": "\x1b[31m", "blue": "\x1b[34m", "magenta": "\x1b[35m",
}

def color(text, name):
    return f"{C[name]}{text}{C['reset']}" if USE_COLOR else text

def stamp(epoch=None):
    value = dt.datetime.now().astimezone() if epoch is None else dt.datetime.fromtimestamp(epoch).astimezone()
    return value.isoformat(timespec="milliseconds")

def is_sensitive(name):
    low = str(name).strip().lower()
    return low in SENSITIVE_EXACT or bool(SENSITIVE.search(low))

def safe_text(value):
    """Keep text readable without letting remote control characters affect the terminal."""
    if value is None:
        return ""
    value = str(value)
    out = []
    for ch in value:
        code = ord(ch)
        if ch in "\n\t\r" or code >= 32:
            # Escape DEL and C1 controls as well as ordinary terminal ESC sequences.
            if code == 127 or 128 <= code <= 159:
                out.append(f"\\x{code:02x}")
            else:
                out.append(ch)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)

def redact_url(url):
    if not REDACT:
        return url
    try:
        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            _, host = netloc.rsplit("@", 1)
            netloc = "[REDACTED]@" + host
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "[REDACTED]" if is_sensitive(key) else value))
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query, doseq=True), parts.fragment))
    except Exception:
        return url

def redact_object(value):
    if not REDACT:
        return value
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if is_sensitive(k) else redact_object(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    return value

def header_pairs(message):
    result = []
    try:
        pairs = message.headers.items(multi=True)
    except TypeError:
        pairs = message.headers.items()
    for key, value in pairs:
        shown = "[REDACTED]" if REDACT and is_sensitive(key) else safe_text(value)
        result.append((safe_text(key), shown))
    return result

def render_body(message):
    raw = getattr(message, "content", None)
    if raw is None:
        raw = b""
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = bytes(raw)
    byte_count = len(raw_bytes)
    ctype = str(message.headers.get("content-type", ""))
    if not SHOW_BODY:
        return {"text": "[body omitted by --no-body]", "kind": "omitted", "bytes": byte_count, "truncated": False, "content_type": ctype}
    if byte_count == 0:
        return {"text": "", "kind": "empty", "bytes": 0, "truncated": False, "content_type": ctype}

    mime = ctype.split(";", 1)[0].strip().lower()
    textual = (
        mime.startswith("text/") or mime in {
            "application/json", "application/ld+json", "application/xml", "application/javascript",
            "application/x-www-form-urlencoded", "application/graphql", "application/yaml",
            "application/x-yaml", "application/xhtml+xml",
        } or mime.endswith("+json") or mime.endswith("+xml") or mime.endswith("+yaml")
    )
    if not textual:
        return {"text": f"[binary body omitted: {mime or 'unknown content type'}, {byte_count} bytes]", "kind": "binary", "bytes": byte_count, "truncated": False, "content_type": ctype}

    try:
        text = message.get_text(strict=False)
        if text is None:
            text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.decode("utf-8", errors="replace")

    # Redact structured payload fields before applying the display limit.
    if REDACT and (mime == "application/json" or mime.endswith("+json")):
        try:
            obj = json.loads(text)
            text = json.dumps(redact_object(obj), ensure_ascii=False, indent=2)
        except Exception:
            pass
    elif REDACT and mime == "application/x-www-form-urlencoded":
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
            text = urlencode([(k, "[REDACTED]" if is_sensitive(k) else v) for k, v in pairs], doseq=True)
        except Exception:
            pass

    text = safe_text(text)
    encoded_text = text.encode("utf-8", errors="replace")
    truncated = len(encoded_text) > BODY_LIMIT
    if truncated:
        # Enforce the limit in bytes while keeping valid UTF-8.
        text = encoded_text[:BODY_LIMIT].decode("utf-8", errors="ignore")
        text += f"\n… [truncated; original message body was {byte_count} bytes]"
    return {"text": text, "kind": "text", "bytes": byte_count, "truncated": truncated, "content_type": ctype}

def md_fence(text):
    runs = re.findall(r"`+", text or "")
    return "`" * max(3, max((len(run) for run in runs), default=0) + 1)

def write_markdown(text):
    with open(LOG_PATH, "a", encoding="utf-8") as file:
        file.write(text)
        if not text.endswith("\n"):
            file.write("\n")
        file.flush()

def write_jsonl(obj):
    if not JSONL_PATH:
        return
    with open(JSONL_PATH, "a", encoding="utf-8") as file:
        file.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
        file.flush()

def terminal_block(label, text, label_color="blue"):
    print(color("  " + label, label_color), flush=True)
    if text:
        for line in text.splitlines() or [""]:
            print("    " + line, flush=True)
    else:
        print("    (empty)", flush=True)

def show_headers(pairs):
    if not pairs:
        return "(none)"
    width = min(max(len(k) for k, _ in pairs), 32)
    return "\n".join(f"{k:<{width}} : {v}" for k, v in pairs)

def show_message(label, message, url_for_display=None):
    headers = header_pairs(message)
    body = render_body(message)
    request_line = ""
    if label == "Request":
        request_line = f"{message.method} {url_for_display or redact_url(message.url)}"
    md = [f"### {label}"]
    if request_line:
        md.extend(["", f"`{request_line}`"])
    md.extend(["", "**Headers**", "", "```text", show_headers(headers), "```"])
    md.extend(["", f"**Body** — {body['bytes']} bytes; {body['content_type'] or 'content type not specified'}", ""])
    if body["text"]:
        fence = md_fence(body["text"])
        language = "json" if (body["content_type"].split(";", 1)[0].strip().lower().endswith("json")) else "text"
        md.extend([f"{fence}{language}", body["text"], fence])
    else:
        md.append("_(empty body)_")
    return headers, body, "\n".join(md)

class HttpWatch:
    def __init__(self):
        self.count = 0

    def _record(self, flow, failed=False):
        self.count += 1
        req = flow.request
        if req is None:
            return
        request_url = redact_url(req.url)
        req_headers, req_body, req_md = show_message("Request", req, request_url)
        timestamp = stamp(getattr(req, "timestamp_start", None))
        duration = None
        if flow.response is not None:
            start = getattr(req, "timestamp_start", None)
            end = getattr(flow.response, "timestamp_end", None)
            if start is not None and end is not None:
                duration = max(0.0, end - start)
        response = flow.response
        if response is not None:
            res_headers, res_body, res_md = show_message("Response", response)
            status = int(response.status_code)
            reason = safe_text(getattr(response, "reason", "") or "")
            status_line = f"{status} {reason}".strip()
            error = None
        else:
            res_headers, res_body = [], {"text": "", "kind": "empty", "bytes": 0, "truncated": False, "content_type": ""}
            res_md = "### Response\n\n_(no HTTP response received)_"
            status = None
            status_line = "REQUEST FAILED"
            error = safe_text(getattr(getattr(flow, "error", None), "msg", "Connection failed"))
        if duration is not None:
            duration_label = f"{duration:.3f}s"
        else:
            duration_label = "n/a"
        title = f"## {self.count:04d} · {safe_text(req.method)} {request_url} · {status_line}"
        record_md = "\n\n" + title + f"\n\n- Time: {timestamp}\n- Duration: {duration_label}\n\n" + req_md + "\n\n" + res_md
        if error:
            record_md += "\n\n**Error**\n\n```text\n" + error + "\n```"
        record_md += "\n"
        write_markdown(record_md)

        if USE_COLOR:
            if status is None or status >= 500:
                status_color = "red"
            elif status >= 400:
                status_color = "yellow"
            elif status >= 300:
                status_color = "cyan"
            else:
                status_color = "green"
        else:
            status_color = "green"
        print("\n" + color("━" * 76, "dim"), flush=True)
        print(color(f"#{self.count:04d}  {req.method}  {request_url}", "bold"), flush=True)
        print(color(f"      {status_line}   ·   {duration_label}   ·   {timestamp}", status_color), flush=True)
        terminal_block("REQUEST HEADERS", show_headers(req_headers), "cyan")
        if req_body["text"]:
            terminal_block(f"REQUEST BODY ({req_body['bytes']} bytes)", req_body["text"], "blue")
        terminal_block("RESPONSE HEADERS", show_headers(res_headers), "magenta")
        if response is not None and res_body["text"]:
            terminal_block(f"RESPONSE BODY ({res_body['bytes']} bytes)", res_body["text"], status_color)
        if error:
            terminal_block("ERROR", error, "red")

        record = {
            "sequence": self.count,
            "timestamp": timestamp,
            "duration_seconds": duration,
            "request": {"method": safe_text(req.method), "url": request_url, "headers": req_headers, "body": req_body},
            "response": None if response is None else {"status": status, "reason": reason, "headers": res_headers, "body": res_body},
            "error": error,
        }
        write_jsonl(record)

    def response(self, flow: http.HTTPFlow):
        self._record(flow)

    def error(self, flow: http.HTTPFlow):
        if flow.response is None:
            self._record(flow, failed=True)

addons = [HttpWatch()]
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="httpwatch",
        description="Run a shell command with an HTTP(S) inspection proxy and neatly log each exchange.",
        epilog=(
            "Example: httpwatch -- 'curl -sS https://httpbin.org/json'\n"
            "For pipelines or redirects, quote the entire shell command as shown."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--log", metavar="PATH", help="Markdown log path (default: ./httpwatch-<timestamp>.md)")
    parser.add_argument("--jsonl", action="store_true", help="also write a machine-readable JSON Lines sidecar")
    parser.add_argument("--no-body", action="store_true", help="log request/response metadata and headers, but not bodies")
    parser.add_argument("--max-body", type=int, default=65536, metavar="BYTES", help="maximum displayed body size per message (default: 65536)")
    parser.add_argument("--no-redact", action="store_true", help="disable default redaction of sensitive headers, query parameters, JSON and form fields")
    parser.add_argument("--no-color", action="store_true", help="disable colors in the terminal")
    parser.add_argument("--record-command", action="store_true", help="store the raw command in the log (may expose command-line secrets)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="shell command, after --")
    args = parser.parse_args()
    if args.max_body < 0:
        parser.error("--max-body must be zero or greater")
    args.command = list(args.command)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing shell command; use: httpwatch -- 'curl https://example.com'")
    return args


def choose_log_path(path_arg: str | None) -> Path:
    if path_arg:
        path = Path(path_arg).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise FileExistsError(f"log already exists: {path} (choose another --log path)")
        return path
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    base = Path.cwd() / f"httpwatch-{stamp}.md"
    candidate = base
    counter = 1
    while candidate.exists():
        candidate = base.with_name(f"{base.stem}-{counter}{base.suffix}")
        counter += 1
    return candidate.resolve()


def create_private_file(path: Path, initial_text: str = "") -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(initial_text)


def choose_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_proxy(proc: subprocess.Popen, port: int, ca_cert: Path, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"mitmdump exited during startup with exit code {proc.returncode}")
        if ca_cert.is_file():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError as exc:
                last_error = exc
        time.sleep(0.1)
    message = f"timed out waiting for mitmdump on 127.0.0.1:{port} and CA certificate {ca_cert}"
    if last_error:
        message += f" ({last_error})"
    raise TimeoutError(message)


def candidate_ca_files(original_env: dict[str, str]) -> list[Path]:
    candidates: list[Path] = []
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "PIP_CERT"):
        value = original_env.get(name)
        if value:
            candidates.append(Path(value).expanduser())
    try:
        default_file = ssl.get_default_verify_paths().cafile
        if default_file:
            candidates.append(Path(default_file))
    except Exception:
        pass
    for fallback in (
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/pki/tls/certs/ca-bundle.crt"),
        Path("/etc/ssl/ca-bundle.pem"),
    ):
        candidates.append(fallback)
    try:
        import certifi  # type: ignore
        candidates.append(Path(certifi.where()))
    except Exception:
        pass
    unique: list[Path] = []
    seen = set()
    for item in candidates:
        try:
            resolved = item.resolve()
        except OSError:
            continue
        if resolved not in seen and resolved.is_file():
            seen.add(resolved)
            unique.append(resolved)
    return unique


def build_ca_bundle(bundle_path: Path, mitm_ca: Path, original_env: dict[str, str]) -> None:
    chunks: list[str] = []
    for ca_file in candidate_ca_files(original_env):
        try:
            data = ca_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "-----BEGIN CERTIFICATE-----" in data:
            chunks.append(data.rstrip())
    try:
        mitm_text = mitm_ca.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"could not read mitmproxy CA certificate at {mitm_ca}: {exc}") from exc
    if "-----BEGIN CERTIFICATE-----" not in mitm_text:
        raise RuntimeError(f"the mitmproxy CA file does not look like a PEM certificate: {mitm_ca}")
    chunks.append(mitm_text.rstrip())
    if not chunks:
        raise RuntimeError("could not assemble a CA bundle")
    bundle_path.write_text("\n\n".join(chunks) + "\n", encoding="utf-8")
    try:
        bundle_path.chmod(0o600)
    except OSError:
        pass


def make_shell_command(items: list[str]) -> str:
    # When the whole command is supplied as one quoted argument, preserve it byte-for-byte.
    # Otherwise shell-quote the argument vector so spaces/quotes in individual arguments survive.
    if len(items) == 1:
        return items[0]
    return shlex.join(items)


def main() -> int:
    args = parse_args()
    if os.name != "posix":
        print("httpwatch currently requires a POSIX environment with bash (Linux/macOS).", file=sys.stderr)
        return 2
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        print("error: mitmdump was not found. Install mitmproxy first, for example:", file=sys.stderr)
        print("  pipx install mitmproxy", file=sys.stderr)
        print("Then ensure pipx's app directory is on PATH and retry.", file=sys.stderr)
        return 127
    bash = shutil.which("bash")
    if not bash:
        print("error: bash was not found on PATH.", file=sys.stderr)
        return 127

    try:
        log_path = choose_log_path(args.log)
    except (OSError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    jsonl_path = log_path.with_suffix(".jsonl") if args.jsonl else None
    if jsonl_path and jsonl_path.exists():
        print(f"error: JSONL log already exists: {jsonl_path}", file=sys.stderr)
        return 2

    command_text = make_shell_command(args.command)
    start = dt.datetime.now().astimezone()
    common_header = (
        "# HTTP Watch capture\n\n"
        f"- Started: {start.isoformat(timespec='seconds')}\n"
        f"- Host: `{socket.gethostname()}`\n"
        f"- Body logging: {'disabled' if args.no_body else f'enabled, max {args.max_body} bytes per message'}\n"
        f"- Redaction: {'disabled' if args.no_redact else 'enabled for common sensitive headers, URL query keys, JSON fields and form fields'}\n"
    )
    safe_command = command_text.replace("`", "\\`")
    log_header = common_header + (
        f"- Command: `{safe_command}`\n" if args.record_command else
        "- Command: _(not stored; use `--record-command` to include it)_\n"
    )
    try:
        create_private_file(log_path, log_header + "\n---\n")
        if jsonl_path:
            create_private_file(jsonl_path, "")
    except OSError as exc:
        print(f"error: could not create log file: {exc}", file=sys.stderr)
        try:
            log_path.unlink(missing_ok=True)
        except Exception:
            pass
        return 2

    print(f"HTTP Watch {VERSION}")
    print(f"Markdown log : {log_path}")
    if jsonl_path:
        print(f"JSONL log    : {jsonl_path}")
    print("Redaction    : " + ("OFF — sensitive values may be written to disk" if args.no_redact else "ON (best-effort)"))
    print("Body logging : " + ("OFF" if args.no_body else f"ON (up to {args.max_body} bytes per message)"))
    print("Proxy        : local-only; command traffic is not sent through a public proxy")
    print("\nStarting capture. Press Ctrl-C to interrupt the command.\n")

    original_env = os.environ.copy()
    exit_code = 1
    proxy_proc: subprocess.Popen | None = None
    temp_dir_obj: tempfile.TemporaryDirectory | None = None
    command_proc: subprocess.Popen | None = None
    try:
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="httpwatch-")
        temp_dir = Path(temp_dir_obj.name)
        addon_path = temp_dir / "httpwatch_addon.py"
        addon_path.write_text(ADDON_SOURCE, encoding="utf-8")
        port = choose_ephemeral_port()
        proxy_url = f"http://127.0.0.1:{port}"
        conf_dir = Path.home() / ".mitmproxy"
        ca_cert = conf_dir / "mitmproxy-ca-cert.pem"

        env_for_addon = original_env.copy()
        env_for_addon.update({
            "HTTPWATCH_LOG_PATH": str(log_path),
            "HTTPWATCH_JSONL_PATH": str(jsonl_path) if jsonl_path else "",
            "HTTPWATCH_BODY_LIMIT": str(args.max_body),
            "HTTPWATCH_SHOW_BODY": "0" if args.no_body else "1",
            "HTTPWATCH_REDACT": "0" if args.no_redact else "1",
            "HTTPWATCH_COLOR": "0" if args.no_color or not sys.stdout.isatty() else "1",
        })
        proxy_cmd = [
            mitmdump, "--quiet", "--listen-host", "127.0.0.1", "--listen-port", str(port),
            "--set", "block_global=false", "--set", f"confdir={conf_dir}", "-s", str(addon_path),
        ]
        proxy_proc = subprocess.Popen(proxy_cmd, env=env_for_addon)
        wait_for_proxy(proxy_proc, port, ca_cert)

        ca_bundle = temp_dir / "combined-ca-bundle.pem"
        build_ca_bundle(ca_bundle, ca_cert, original_env)
        child_env = original_env.copy()
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            child_env[name] = proxy_url
        # Include loopback traffic too; only the proxy process itself is outside this environment.
        child_env["NO_PROXY"] = ""
        child_env["no_proxy"] = ""
        # Widely honored trust configuration, preserving existing/system roots alongside mitmproxy's CA.
        for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "PIP_CERT"):
            child_env[name] = str(ca_bundle)
        child_env["NODE_EXTRA_CA_CERTS"] = str(ca_bundle)

        command_proc = subprocess.Popen([bash, "-c", command_text], env=child_env)
        exit_code = command_proc.wait()
    except KeyboardInterrupt:
        print("\nInterrupted; stopping the command and proxy…", file=sys.stderr)
        exit_code = 130
        if command_proc and command_proc.poll() is None:
            command_proc.terminate()
            try:
                command_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                command_proc.kill()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        if command_proc and command_proc.poll() is None:
            command_proc.terminate()
            try:
                command_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                command_proc.kill()
                command_proc.wait()
        if proxy_proc and proxy_proc.poll() is None:
            proxy_proc.terminate()
            try:
                proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
        finished = dt.datetime.now().astimezone()
        try:
            with open(log_path, "a", encoding="utf-8") as file:
                file.write("\n---\n\n")
                file.write(f"Capture finished: {finished.isoformat(timespec='seconds')}\n\n")
                file.write(f"Command exit code: `{exit_code}`\n")
        except OSError as exc:
            print(f"warning: could not finalize Markdown log: {exc}", file=sys.stderr)
        if temp_dir_obj:
            temp_dir_obj.cleanup()

    print(f"\nCapture finished with exit code {exit_code}.")
    print(f"Readable log: {log_path}")
    if jsonl_path:
        print(f"Structured log: {jsonl_path}")
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
