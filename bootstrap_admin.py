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
    """Block until Overleaf's web service responds 2xx/3xx on /login."""
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


def _run_create_user(email: str) -> str:
    """Run create-user.mjs --admin --email=<email>; parse the
    password-reset URL from stdout.

    Returns the passwordResetToken.
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

    # The script prints a "Please visit the following URL ..."
    # block followed by the URL on its own line.  Match the URL.
    m = re.search(
        r"https?://[^\s]+/user/password/set\?[^\s]+",
        output,
    )
    if not m:
        # Fallback: maybe Overleaf changed the URL shape.  Try a
        # broader match: any URL with a passwordResetToken query.
        m = re.search(
            r"https?://[^\s]*passwordResetToken=[a-zA-Z0-9._-]+[^\s]*",
            output,
        )
    if not m:
        raise RuntimeError(
            f"create-user.mjs did not print a password-reset URL.  "
            f"Output:\n{output}"
        )
    url = m.group(0)
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    token_list = qs.get("passwordResetToken", [])
    if not token_list:
        raise RuntimeError(
            f"password-reset URL is missing passwordResetToken query: {url}"
        )
    return token_list[0]


def _set_password(token: str, password: str) -> None:
    """POST /user/password/set with the reset token.

    Overleaf's set-password endpoint accepts JSON
    ``{passwordResetToken, password}`` and returns 200 on
    success.  No CSRF token required: passwordResetToken IS the
    CSRF mechanism for this flow (single-use, server-side
    bound).
    """
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


def main() -> int:
    if os.path.exists(CRED_FILE):
        print(f"[bootstrap] {CRED_FILE} exists; skipping admin creation")
        return 0

    print("[bootstrap] Waiting for Overleaf web service to be ready")
    _wait_for_overleaf_ready()

    password = _generate_password()
    token = _run_create_user(ADMIN_EMAIL)
    print(f"[bootstrap] Got password-reset token; setting password for {ADMIN_EMAIL}")
    _set_password(token, password)

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
