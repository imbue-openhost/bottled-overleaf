"""OpenHost auto-login auth-proxy for Overleaf Community Edition.

Pattern B (auto-login sidecar).  When the OpenHost router stamps
``X-OpenHost-Is-Owner: true`` on an HTML navigation and the
visitor has no Overleaf ``overleaf.sid`` cookie, the proxy:

  1. GET /login over loopback to harvest the CSRF token from the
     embedded ``meta name="ol-csrfToken"`` tag and the matching
     ``overleaf.sid`` cookie.
  2. POST /login with JSON body
     ``{"email":"...","password":"...","_csrf":"..."}`` plus the
     same ``overleaf.sid`` cookie + ``X-Csrf-Token`` header.
     Overleaf returns 200 with ``{"redir":"/project"}`` and
     ``Set-Cookie: overleaf.sid=<new-sid>; HttpOnly`` (rotated).
  3. 302 the visitor to their original URL with the rotated
     ``overleaf.sid`` cookie set.

Defense in depth: ALWAYS strip client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` before forwarding.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
OVERLEAF_SID_COOKIE = "overleaf.sid"

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 60
MAX_BODY_BYTES = 64 * 1024 * 1024  # Overleaf project uploads

# Overleaf's login endpoint.
OVERLEAF_LOGIN_PATH = "/login"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_admin_creds(cred_file: str) -> tuple[str, str] | None:
    """Read OVERLEAF_ADMIN_EMAIL / OVERLEAF_ADMIN_PASSWORD from the
    on-disk credentials file written by bootstrap_admin.py.
    """
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None
    email = password = None
    for line in content.splitlines():
        m = re.match(
            r"^\s*(?:export\s+)?(OVERLEAF_ADMIN_EMAIL|OVERLEAF_ADMIN_PASSWORD)\s*=\s*(.*?)\s*$",
            line,
        )
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "OVERLEAF_ADMIN_EMAIL":
            email = val
        elif key == "OVERLEAF_ADMIN_PASSWORD":
            password = val
    if email and password:
        return email, password
    return None


def _split_set_cookie(set_cookie_header: str) -> list[str]:
    """Heuristic split of a comma-folded Set-Cookie header back
    into individual cookie strings.  Same approach as the
    formbricks proxy.
    """
    if not set_cookie_header:
        return []
    parts: list[str] = []
    buf = ""
    for chunk in set_cookie_header.split(", "):
        if buf and re.match(r"^[A-Za-z][A-Za-z0-9_.-]*=", chunk) and "; " in chunk:
            parts.append(buf)
            buf = chunk
        elif buf:
            buf += ", " + chunk
        else:
            buf = chunk
    if buf:
        parts.append(buf)
    return parts


def _login_to_overleaf(
    upstream_host: str,
    upstream_port: int,
    email: str,
    password: str,
    forwarded_host: str,
) -> str | None:
    """Run Overleaf's CSRF + /login dance on loopback.

    Returns the rotated ``overleaf.sid=...; ...`` Set-Cookie
    string to echo back on the 302, or None on failure.
    """
    host_header = forwarded_host or f"{upstream_host}:{upstream_port}"

    try:
        # Step 1: GET /login to mint the CSRF token + initial sid.
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=15)
        conn.request(
            "GET",
            "/login",
            headers={
                "Host": host_header,
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": host_header,
                "Accept": "text/html",
            },
        )
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            log.warning("auto-login: GET /login returned %d", resp.status)
            conn.close()
            return None
        # Overleaf embeds the CSRF token in a <meta> tag:
        #   <meta name="ol-csrfToken" content="...">
        # We pull it out with a regex; the token is base64url-ish
        # and never contains < or " so the regex is unambiguous.
        m = re.search(
            rb'<meta\s+name=["\']ol-csrfToken["\']\s+content=["\']([^"\']+)["\']',
            body,
        )
        if not m:
            log.warning(
                "auto-login: no ol-csrfToken meta tag in /login HTML "
                "(Overleaf version may have changed); body excerpt: %r",
                body[:300],
            )
            conn.close()
            return None
        csrf_token = m.group(1).decode("ascii")

        # Capture the initial overleaf.sid cookie — Overleaf binds
        # the CSRF token to this session so we MUST send the same
        # cookie on the POST.
        initial_set_cookie = resp.getheader("Set-Cookie") or ""
        sid_cookie_pair = None
        for cookie_str in _split_set_cookie(initial_set_cookie):
            head = cookie_str.split(";", 1)[0].strip()
            if head.startswith(OVERLEAF_SID_COOKIE + "="):
                sid_cookie_pair = head
                break
        if sid_cookie_pair is None:
            log.warning(
                "auto-login: GET /login response missing %s Set-Cookie "
                "(initial Set-Cookie: %r)",
                OVERLEAF_SID_COOKIE,
                initial_set_cookie[:200],
            )
            conn.close()
            return None
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: GET /login failed: %s", exc)
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        return None

    # Step 2: POST /login with JSON.
    try:
        payload = json.dumps({
            "email": email,
            "password": password,
            "_csrf": csrf_token,
        }).encode("utf-8")
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=15)
        conn.request(
            "POST",
            "/login",
            body=payload,
            headers={
                "Host": host_header,
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": host_header,
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Accept": "application/json",
                "Cookie": sid_cookie_pair,
                "X-Csrf-Token": csrf_token,
            },
        )
        resp = conn.getresponse()
        body = resp.read()
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: POST /login failed: %s", exc)
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    if resp.status != 200:
        log.warning(
            "auto-login: POST /login returned %d; body excerpt: %r",
            resp.status,
            body[:300],
        )
        return None
    try:
        data = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        data = {}
    if "redir" not in data and not data:
        log.warning(
            "auto-login: POST /login body missing 'redir' (likely auth "
            "failure); excerpt: %r",
            body[:300],
        )
        return None

    # Capture the rotated overleaf.sid cookie.  Express-session's
    # default behaviour is to regenerate the sid on login; the new
    # cookie is in the response headers.
    set_cookie = resp.getheader("Set-Cookie") or ""
    rotated_cookie = None
    for cookie_str in _split_set_cookie(set_cookie):
        head = cookie_str.split(";", 1)[0].strip()
        if head.startswith(OVERLEAF_SID_COOKIE + "="):
            # We want the WHOLE cookie line (with attributes like
            # HttpOnly, Path=/, Max-Age=...) so the browser sets
            # exactly the same cookie Overleaf intended.
            rotated_cookie = cookie_str
            break
    if rotated_cookie is None:
        log.warning(
            "auto-login: POST /login 200 but no rotated %s in Set-Cookie",
            OVERLEAF_SID_COOKIE,
        )
        return None
    return rotated_cookie


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 80
    cred_file: str = "/data/app_data/overleaf/admin-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        if self.path == "/_healthz":
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "3")
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(b"ok\n")
            except OSError:
                pass
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_session = OVERLEAF_SID_COOKIE in cookies

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET" and "text/html" in accept.lower()
        )
        # Don't auto-login on /login itself, /api/* (Git integration etc.),
        # /socket.io/* (real-time), or static assets.
        is_app_path = (
            not self.path.startswith("/login")
            and not self.path.startswith("/api/")
            and not self.path.startswith("/socket.io/")
            and not self.path.startswith("/javascripts/")
            and not self.path.startswith("/stylesheets/")
            and not self.path.startswith("/fonts/")
            and not self.path.startswith("/img/")
            and not self.path.startswith("/assets/")
            and self.path != "/favicon.ico"
        )

        if is_owner and not has_session and is_html_navigation and is_app_path:
            if self._maybe_auto_login():
                return

        self._proxy()

    def _maybe_auto_login(self) -> bool:
        creds = _read_admin_creds(self.cred_file)
        if creds is None:
            log.warning(
                "auto-login: credentials file missing or unreadable at %s; "
                "falling through to manual login",
                self.cred_file,
            )
            return False

        email, password = creds
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        rotated_cookie = _login_to_overleaf(
            self.upstream_host, self.upstream_port, email, password,
            forwarded_host,
        )
        if rotated_cookie is None:
            return False

        target_path = self.path or "/"
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            self.send_header("Set-Cookie", rotated_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted Overleaf session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        if not any(k.lower() == "x-forwarded-proto" for k, _ in cleaned_headers):
            cleaned_headers.append(("X-Forwarded-Proto", "https"))

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 80)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/overleaf/admin-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
