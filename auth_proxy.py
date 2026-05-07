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
import selectors
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

# WebSocket / streaming constants.  Overleaf's editor uses a Socket.IO
# connection (over WebSocket) at /socket.io/* for live document edits,
# cursor positions, and save indicators.  The auth-proxy must forward
# the upgrade verbatim — without this, the SPA falls back to long
# polling and the editor takes ~1 minute to load while the SPA
# decides the websocket is dead.
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 6 * 60 * 60
HEADER_LINE_CAP = 64 * 1024

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
        initial_raw_cookies = [
            v for k, v in resp.getheaders() if k.lower() == "set-cookie"
        ]
        sid_cookie_pair = None
        for cookie_str in initial_raw_cookies:
            head = cookie_str.split(";", 1)[0].strip()
            if head.startswith(OVERLEAF_SID_COOKIE + "="):
                sid_cookie_pair = head
                break
        if sid_cookie_pair is None:
            log.warning(
                "auto-login: GET /login response missing %s Set-Cookie "
                "(raw Set-Cookies: %r)",
                OVERLEAF_SID_COOKIE,
                initial_raw_cookies,
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
    #
    # Use getheaders() rather than getheader("Set-Cookie") to
    # preserve individual Set-Cookie lines — getheader() folds
    # repeated headers with ", " which breaks the splitter when
    # NextAuth-like Expires=... attributes contain commas.
    raw_set_cookies = [
        v for k, v in resp.getheaders() if k.lower() == "set-cookie"
    ]
    rotated_cookie = None
    for cookie_str in raw_set_cookies:
        head = cookie_str.split(";", 1)[0].strip()
        if head.startswith(OVERLEAF_SID_COOKIE + "="):
            # We want the WHOLE cookie line (with attributes like
            # HttpOnly, Path=/, Max-Age=...) so the browser sets
            # exactly the same cookie Overleaf intended.
            rotated_cookie = cookie_str
            break
    if rotated_cookie is None:
        log.warning(
            "auto-login: POST /login 200 but no rotated %s in Set-Cookie "
            "(raw Set-Cookies: %r)",
            OVERLEAF_SID_COOKIE,
            raw_set_cookies,
        )
        return None
    return rotated_cookie


class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 lets us forward Transfer-Encoding: chunked from upstream
    # untouched and supports Range responses (206) for project file
    # downloads.  Default is HTTP/1.0 which forces close-per-request
    # and rejects chunked encoding.
    protocol_version = "HTTP/1.1"

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

        # WebSocket upgrades bypass auto-login + body-buffering and go
        # straight to bidirectional forwarding.  By the time a WS
        # upgrade is requested the SPA has already established its
        # session (overleaf.sid cookie present) and Socket.IO has
        # done its polling-mode handshake, so no auto-login dance is
        # needed.
        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_session = OVERLEAF_SID_COOKIE in cookies

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET" and "text/html" in accept.lower()
        )
        # Skip auto-login on machine-consumed paths (the editor's
        # XHR API, the real-time websocket handshake, static assets,
        # and the proxy's own /_healthz).  Notably we DO auto-login
        # on GET /login: Overleaf 302's there after a session expiry
        # or an explicit logout, and the whole point of the SSO is
        # that the owner shouldn't have to click "sign in" — when
        # they land there, mint a fresh session and redirect them
        # back to the editor.
        #
        # Auto-login is only triggered for the OpenHost-router-stamped
        # owner; it never fires for unauthenticated visitors (they
        # hit the OpenHost router's own /login page first), so this
        # path doesn't expose the Overleaf admin to the public.
        is_app_path = (
            not self.path.startswith("/api/")
            and not self.path.startswith("/socket.io/")
            and not self.path.startswith("/javascripts/")
            and not self.path.startswith("/stylesheets/")
            and not self.path.startswith("/fonts/")
            and not self.path.startswith("/img/")
            and not self.path.startswith("/assets/")
            and not self.path.startswith("/js/")
            and not self.path.startswith("/css/")
            and self.path != "/favicon.ico"
            and self.path != "/favicon.svg"
            and self.path != "/_healthz"
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

    # ---------- WebSocket forwarding (Socket.IO at /socket.io/*) ----------

    def _is_websocket_upgrade(self) -> bool:
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        """Forward a WebSocket upgrade verbatim by raw-socket relay.

        Overleaf's editor uses Socket.IO over WebSocket at
        ``/socket.io/*`` for live document state.  Without this method
        the auth-proxy strips the Upgrade header (it's listed as
        hop-by-hop), forwards as plain HTTP, and the SPA falls back
        to long polling — which manifests as ~1 minute of editor
        load time while the SPA decides the websocket is dead.
        """
        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            host_header = forwarded_host or f"{self.upstream_host}:{self.upstream_port}"
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(f"Host: {host_header}\r\n")
            )
            for k, v in cleaned:
                request_bytes.extend(self._encode_header_bytes(f"{k}: {v}\r\n"))
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            if not head_bytes.startswith(b"HTTP/1.1 101"):
                first_line = head_bytes.split(b"\r\n", 1)[0].decode(
                    "latin-1", errors="replace"
                )
                log.info("upstream rejected websocket upgrade: %s", first_line)
                return

            self._websocket_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client->upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream->client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.info("websocket %s recv failed: %s", direction, exc)
                        return
                    if not chunk:
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info("websocket %s sendall failed: %s", direction, exc)
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

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

        # Long timeout so multi-MiB project uploads / downloads aren't
        # capped at 120s.
        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=STREAM_TIMEOUT_SECONDS
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

            # Send response headers immediately, before reading body.
            # Forwarding upstream's Content-Length / Transfer-Encoding
            # untouched lets Range responses (206 + Content-Range)
            # work for project file downloads, and lets the browser
            # start rendering the editor SPA as soon as the first
            # bytes arrive instead of waiting for the whole 8+ MiB
            # bundle to buffer through the proxy.
            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                # Force one-and-done so we don't have to manage HTTP/1.1
                # keep-alive state between requests on the same TCP
                # connection.
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
            except OSError as exc:
                log.debug("client disconnected during response head: %s", exc)
                upstream.close()
                return

            if self.command != "HEAD":
                try:
                    while True:
                        chunk = upstream.read(STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except OSError as exc:
                            log.debug(
                                "client disconnected mid-stream after %d bytes: %s",
                                len(chunk), exc,
                            )
                            return
                except (OSError, http.client.HTTPException) as exc:
                    log.warning("upstream read error mid-stream: %s", exc)
                    return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
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
