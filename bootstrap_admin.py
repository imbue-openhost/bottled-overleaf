#!/usr/bin/env python3
"""First-boot admin creation for openhost-overleaf.

Overleaf Community Edition has no default admin; on first run
the upstream image leaves the user database empty and presents
a "set password" screen if the operator visits before any user
has been registered.

This bootstrap script:

  1. Runs ``node /overleaf/services/web/modules/server-ce-scripts/
     scripts/create-user.mjs --admin --email=admin@<zone>``.
     The script outputs a "Please visit the following URL to set
     a password" line containing a passwordResetToken.
  2. Parses the URL out of stdout, extracts the token.
  3. POSTs ``/user/password/set`` with the token + a freshly-
     generated 32-character password.
  4. Persists ``admin-credentials.txt`` (mode 0600) for the
     auth-proxy.

Idempotent: if ``$CRED_FILE`` exists, skip everything.

This runs INSIDE the upstream sharelatex/sharelatex container —
``/overleaf`` is the upstream's installation root.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CRED_FILE = os.environ.get(
    "CRED_FILE", "/data/app_data/overleaf/admin-credentials.txt"
)
ADMIN_EMAIL = os.environ.get(
    "OVERLEAF_ADMIN_EMAIL",
    f"admin@{os.environ.get('OPENHOST_ZONE_DOMAIN', 'openhost.local')}",
)
WEB_PORT = int(os.environ.get("OVERLEAF_WEB_PORT", "80"))
OVERLEAF = f"http://127.0.0.1:{WEB_PORT}"
SHARELATEX_DIR = "/overleaf"
CREATE_USER_SCRIPT = (
    f"{SHARELATEX_DIR}/services/web/modules/server-ce-scripts/scripts/"
    "create-user.mjs"
)


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(40))


def _wait_for_overleaf_ready(retries: int = 240, delay: float = 1.0) -> None:
    """Block until Overleaf's web service responds 2xx/3xx on /login.

    /login is the lightest readiness probe — it doesn't touch the
    History service or trigger global-blob loading.  We use a
    deeper probe later (a probe GET on /user/activate with a
    bogus token, expecting 4xx not 5xx) once we're ready to start
    driving the activation flow.
    """
    for i in range(retries):
        try:
            req = urllib.request.Request(f"{OVERLEAF}/login")
            resp = urllib.request.urlopen(req, timeout=3)
            if resp.status < 500:
                return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(delay)
    raise RuntimeError(
        f"Overleaf /login did not respond within {retries * delay:.0f}s"
    )


def _wait_for_activation_ready(retries: int = 60, delay: float = 2.0) -> None:
    """Block until /user/activate stops returning 5xx.

    On a freshly-started overleaf the activation handler 500s for
    ~30-60s while HistoryManager.loadGlobalBlobs spins up against
    Mongo.  We probe with a known-bad token (which after warmup
    yields a 4xx 'invalid token' page rather than a 5xx 'Something
    went wrong' page) before submitting the real activation URL.
    """
    probe = f"{OVERLEAF}/user/activate?token=warmup&user_id=warmup"
    for _ in range(retries):
        try:
            req = urllib.request.Request(probe, headers={"Accept": "text/html"})
            opener = urllib.request.build_opener(_NoRedirect())
            try:
                resp = opener.open(req, timeout=10)
                status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            if status < 500:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(delay)
    # Fall through anyway; _harvest_csrf has its own retry loop.


def _run_create_user(email: str) -> tuple[str, str]:
    """Run create-user.mjs --admin --email=<email>; parse the
    password-reset URL from stdout.

    Returns (token, full_activation_path) where
    full_activation_path is the path+query of the URL relative
    to OVERLEAF_BASE (eg
    "/user/activate?token=...&user_id=...").
    """
    cmd = [
        "node",
        CREATE_USER_SCRIPT,
        "--admin",
        f"--email={email}",
    ]
    print(f"[bootstrap] Running: {' '.join(cmd)}")
    # The web service stores its node_modules under
    # /overleaf/services/web; cwd there so imports resolve.
    proc = subprocess.run(
        cmd,
        cwd=f"{SHARELATEX_DIR}/services/web",
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "NODE_PATH": f"{SHARELATEX_DIR}/services/web/node_modules",
        },
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(
            f"create-user.mjs exited {proc.returncode}; output:\n{output}"
        )

    # Overleaf 5.x prints a "Please visit the following URL ..."
    # block followed by an activation URL with the shape
    #   https://<host>/user/activate?token=<hex>&user_id=<oid>
    # (older Overleaf 4.x used /user/password/set?passwordResetToken=...).
    # The URL appears both in plain stdout AND in a JSON-encoded
    # log line where it's escaped (\").  Restrict the character
    # class to what valid URL chars look like — alphanumerics +
    # the limited punctuation Overleaf actually emits — to avoid
    # picking up trailing JSON quotes / escapes.
    m = re.search(
        r"https?://[A-Za-z0-9._\-/]+/user/activate\?token=[A-Za-z0-9._\-]+(?:&user_id=[A-Za-z0-9]+)?",
        output,
    )
    if not m:
        m = re.search(
            r"https?://[A-Za-z0-9._\-/]+/user/password/set\?passwordResetToken=[A-Za-z0-9._\-]+(?:&[A-Za-z0-9.=&_\-]+)?",
            output,
        )
    if not m:
        raise RuntimeError(
            f"create-user.mjs did not print a password-reset / "
            f"activation URL.  Output:\n{output}"
        )
    url = m.group(0)
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # Activation URL uses "token"; legacy uses "passwordResetToken".
    token: str | None = None
    for key in ("token", "passwordResetToken"):
        if key in qs and qs[key]:
            token = qs[key][0]
            break
    if token is None:
        raise RuntimeError(
            f"URL is missing token / passwordResetToken query: {url}"
        )
    activation_path = parsed.path + ("?" + parsed.query if parsed.query else "")
    return token, activation_path


def _harvest_csrf(activation_path: str, retries: int = 30, delay: float = 2.0) -> tuple[str, str]:
    """GET <activation_path> (e.g. /user/activate?token=<...>&user_id=<oid>)
    to harvest a CSRF token + the matching session cookie.

    Overleaf's set-password POST is CSRF-protected; the token is
    embedded in the activation page's HTML as a <meta
    name="ol-csrfToken" content="..."> tag, and the matching
    session cookie (overleaf.sid) is set in the response headers.
    Both must be sent together on the subsequent POST.

    Retries on 5xx because /user/activate transitively touches
    the History service / global-blob bootstrap, which can throw
    Mongo connect-timeout 500s for the first ~30s after web
    starts even though /login is already serving.

    Returns (csrf_token, session_cookie_header).
    """
    url = f"{OVERLEAF}{activation_path}"
    last_status = 0
    last_body = ""
    last_set_cookie = ""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"Accept": "text/html"})
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            resp = opener.open(req, timeout=15)
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            set_cookie = resp.headers.get("Set-Cookie") or ""
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            set_cookie = exc.headers.get("Set-Cookie") if exc.headers else ""
        last_status = status
        last_body = body
        last_set_cookie = set_cookie
        if status == 200:
            break
        if status < 500:
            break  # 4xx is a real error, no point retrying
        time.sleep(delay)
    if last_status != 200:
        raise RuntimeError(
            f"GET /user/activate returned {last_status} after {retries} retries; "
            f"body excerpt: {last_body[:200]!r}"
        )

    m = re.search(
        r'<meta\s+name=["\']ol-csrfToken["\']\s+content=["\']([^"\']+)["\']',
        last_body,
    )
    if not m:
        raise RuntimeError(
            f"no ol-csrfToken meta tag in /user/activate HTML; "
            f"excerpt: {last_body[:300]!r}"
        )
    csrf_token = m.group(1)

    # Pull the overleaf.sid cookie out of Set-Cookie.
    sid_pair = None
    for cookie_str in (last_set_cookie or "").split(", "):
        head = cookie_str.split(";", 1)[0].strip()
        if head.startswith("overleaf.sid="):
            sid_pair = head
            break
    if sid_pair is None:
        raise RuntimeError(
            "GET /user/activate did not Set-Cookie overleaf.sid"
        )
    return csrf_token, sid_pair


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ARG002
        return None


def _set_password(token: str, activation_path: str, password: str) -> None:
    """POST /user/password/set with the reset token.

    Overleaf's set-password endpoint requires a CSRF token + the
    matching session cookie (it's part of Overleaf's standard
    csurf middleware on every authenticated POST).  We harvest
    both from a prior GET on the activation URL (which already
    contains the token + user_id, so Overleaf accepts the page
    visit + sets the session).
    """
    csrf_token, sid_pair = _harvest_csrf(activation_path)
    payload = json.dumps({
        "passwordResetToken": token,
        "password": password,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OVERLEAF}/user/password/set",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "Accept": "application/json",
            "Cookie": sid_pair,
            "X-Csrf-Token": csrf_token,
            "X-Forwarded-Proto": "https",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        body = resp.read().decode("utf-8", errors="replace")
        status = resp.status
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        status = exc.code
    if status != 200:
        raise RuntimeError(
            f"/user/password/set returned {status}; body excerpt: {body[:200]!r}"
        )


def _delete_user_if_exists(email: str) -> None:
    """Drop any existing user row with the given email so we can
    re-run the create-user.mjs script idempotently.

    Uses mongosh against the local Mongo replica set.  Best-effort:
    if mongosh is missing or the deletion fails, we let create-user.mjs
    surface the error.
    """
    e = email.replace("'", "\\'")
    cmd = [
        "mongosh",
        "--quiet",
        "mongodb://127.0.0.1:27017/sharelatex",
        "--eval",
        f"db.users.deleteOne({{ email: '{e}' }})",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=15)
        print(f"[bootstrap] Deleted any existing user with email {email}: {out.strip()}")
    except subprocess.CalledProcessError as exc:
        print(
            f"[bootstrap] WARNING: could not delete pre-existing user "
            f"{email}: {exc.output.strip() if exc.output else exc}",
            file=sys.stderr,
        )
    except FileNotFoundError:
        # mongosh not in PATH; skip the cleanup.  create-user.mjs
        # will then fail with "user already exists" if applicable.
        pass


def main() -> int:
    if os.path.exists(CRED_FILE):
        print(f"[bootstrap] {CRED_FILE} exists; skipping admin creation")
        return 0

    print("[bootstrap] Waiting for Overleaf /login to be ready")
    _wait_for_overleaf_ready()

    print("[bootstrap] Waiting for Overleaf /user/activate to stop 500ing")
    _wait_for_activation_ready()

    # Drop any prior user row with the same email so create-user.mjs
    # doesn't bail with "Email already registered".  Single-tenant
    # deploy: the only user is the admin we re-create here.
    _delete_user_if_exists(ADMIN_EMAIL)

    password = _generate_password()
    token, activation_path = _run_create_user(ADMIN_EMAIL)
    print(f"[bootstrap] Got password-reset token; setting password for {ADMIN_EMAIL}")
    _set_password(token, activation_path, password)

    os.makedirs(os.path.dirname(CRED_FILE), exist_ok=True)
    fd = os.open(CRED_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(
                "# Overleaf admin credentials, generated by "
                "bootstrap_admin.py on first boot.\n"
                "# Used by auth_proxy.py to mint owner sessions on "
                "demand.\n"
                "# Anyone who can read this file can log in to "
                "Overleaf as admin.\n"
                "#\n"
                "# To rotate: delete this file + the user row in "
                "Mongo, restart the container.\n"
                f"export OVERLEAF_ADMIN_EMAIL='{ADMIN_EMAIL}'\n"
                f"export OVERLEAF_ADMIN_PASSWORD='{password}'\n"
            )
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    print(f"[bootstrap] Persisted admin credentials to {CRED_FILE}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"[bootstrap] uncaught exception: {exc}", file=sys.stderr)
        sys.exit(1)
