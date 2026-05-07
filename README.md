# openhost-overleaf

Overleaf Community Edition (online LaTeX editor) packaged for OpenHost
with one-click owner SSO via Pattern B (auto-login sidecar).

## Topology

```
browser → OpenHost router (subdomain overleaf.<zone>; verifies owner
                          zone_auth, stamps X-OpenHost-Is-Owner)
       → container :8080  (auth_proxy.py — auto-login sidecar)
       → 127.0.0.1:80     (Overleaf upstream nginx + web)
              ├─ 127.0.0.1:27017 (MongoDB, replica set "overleaf")
              └─ 127.0.0.1:6379  (Redis)
```

## Auth flow

1. Owner GETs `/` on `overleaf.<zone>`.  Router stamps
   `X-OpenHost-Is-Owner=true`.
2. `auth_proxy.py` sees no `overleaf.sid` cookie + owner header on an
   HTML navigation; runs the GET-CSRF + POST-`/login` dance over
   loopback using bootstrap-generated admin credentials.
3. Captures the rotated `overleaf.sid` cookie + 302s the browser back
   to the original URL with the cookie set.

## Sharing projects with non-owners

Every Overleaf URL is exposed publicly via `public_paths = ["/"]`,
so the owner can share project links with collaborators who don't
have OpenHost zone accounts.  Access control inside the app is
enforced by Overleaf itself (project sharing is link-token-gated;
project-list is per-user).  Auto-login is gated on the
`X-OpenHost-Is-Owner` header — only the owner gets the admin
session minted automatically; everyone else sees Overleaf's normal
login form.

Flow:

1. Owner shares a project (Share button → invite by email or copy
   a link-share URL).
2. Collaborator opens the URL.  No zone_auth → router lets them
   through (paths are all public).
3. They land on Overleaf's own login form.  Either sign in to an
   existing Overleaf account or register one (Overleaf CE allows
   open registration by default; the owner can lock that down in
   site-admin settings if they want invitation-only).
4. They join the project as a normal Overleaf user.

## Files

  * `openhost.toml` — manifest.  `/_healthz` health check;
    everything else exposed publicly so non-owner collaborators
    can reach Overleaf's own login/register pages.
  * `Dockerfile` — bases on `sharelatex/sharelatex:latest`, adds
    MongoDB 6 + Redis + Python 3.
  * `start.sh` — initialises a single-node Mongo replica set
    (Overleaf 4.x requires it for transactions), starts Redis, runs
    Overleaf via the upstream Phusion `/sbin/my_init`, and supervises
    the auth-proxy.
  * `auth_proxy.py` — owner auto-login sidecar (Pattern B).  Handles
    Overleaf's CSRF + JSON-`/login` flow.
  * `bootstrap_admin.py` — first-boot admin creation.  Runs
    `node create-user.mjs --admin --email=...`, parses the
    password-reset URL from stdout, POSTs `/user/password/set` with
    a freshly-generated 40-character password, and persists creds.

## Why Pattern B (not OIDC)

Overleaf Community Edition does NOT support OIDC SSO; OAuth/OIDC is a
Server Pro–only feature.  Pattern B against the upstream
email/password login form is the only viable approach for CE.  The
auth-proxy POSTs JSON to `/login` with the bootstrap-generated admin
credentials.

## Persistent state

Everything lives under `$OPENHOST_APP_DATA_DIR/`:

  * `data/`   — Overleaf's `/var/lib/overleaf` bind mount (project
    files, compiles, uploads).
  * `mongo/`  — MongoDB data dir.
  * `mongo-log/` — MongoDB log file.
  * `redis/`  — Redis dir (no on-disk persistence; just for pidfile +
    logfile).
  * `admin-credentials.txt` — admin email + password (mode 0600).

## Caveats

  * **First-boot is slow.**  Overleaf's Phusion init brings up
    several Node services (web, clsi, document-updater, real-time,
    contacts, notifications, history, etc.).  First boot can take
    90+s; `/_healthz` returns 200 from the auth-proxy immediately so
    OpenHost's healthcheck doesn't fail.
  * **No sandboxed compiles.**  `SANDBOXED_COMPILES=false` because we
    can't easily run docker-in-docker inside the OpenHost rootless
    podman runtime.  The Community Edition runs the LaTeX compiler
    in the same container; safe for single-tenant use but not for
    sharing with untrusted users.
  * **No SMTP.**  Email confirmation, password reset emails, and
    project-share invite emails are disabled.
  * **MongoDB 6 with replica set.**  Overleaf 4.x uses transactions,
    which require a replica set.  We initialise a single-node replica
    set named "overleaf" on first boot.  If you ever need to back
    up Mongo, use the standard `mongodump` against the replica set.
