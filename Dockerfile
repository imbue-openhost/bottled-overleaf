# Overleaf Community Edition + bundled MongoDB + Redis + auth-proxy
# packaged for OpenHost.
#
# Layout:
#
#   browser → OpenHost router (subdomain overleaf.<zone>; verifies
#                              owner zone_auth, stamps
#                              X-OpenHost-Is-Owner)
#          → container :8080  (auth_proxy.py)
#          → 127.0.0.1:80     (Overleaf web service / nginx)
#                ├─ 127.0.0.1:27017 (Mongo)
#                └─ 127.0.0.1:6379  (Redis)
#
# Auth flow on first owner visit:
#
#   1. Owner GETs / on overleaf.<zone>.  Router stamps
#      X-OpenHost-Is-Owner=true.
#   2. auth_proxy.py sees no overleaf.sid cookie + owner header;
#      runs the GET-CSRF + POST-/login dance over loopback using
#      the bootstrap-generated admin credentials.
#   3. Captures the rotated overleaf.sid cookie + 302s the
#      browser to the original URL with the cookie set.
#
# We base on sharelatex/sharelatex:latest (Phusion/baseimage,
# Ubuntu, ~1.1 GiB) and add MongoDB + Redis + Python.

FROM docker.io/sharelatex/sharelatex:latest

USER root

ARG DEBIAN_FRONTEND=noninteractive

# Phusion baseimage uses /sbin/my_init as PID-1 by default; we
# replace that with our own start.sh which supervises mongo +
# redis + the upstream services + the auth-proxy.

# Add MongoDB 6 + Redis from upstream apt repos.  The base image
# is Ubuntu 22.04 (jammy).
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        gnupg \
        wget \
        ca-certificates \
        curl \
        lsb-release \
        python3 \
        tini \
        gosu \
        redis-server \
 && wget -qO- https://www.mongodb.org/static/pgp/server-6.0.asc \
        | gpg --dearmor -o /usr/share/keyrings/mongodb-6.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/mongodb-6.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
        > /etc/apt/sources.list.d/mongodb.list \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        mongodb-org-server \
        mongodb-org-shell \
        mongodb-org-mongos \
        mongodb-org-tools \
 && rm -rf /var/lib/apt/lists/*

# Application files.  COPY in rootless podman doesn't always
# preserve the executable bit; force 0755 explicitly.
COPY start.sh             /opt/openhost-overleaf/start.sh
COPY auth_proxy.py        /opt/openhost-overleaf/auth_proxy.py
COPY bootstrap_admin.py   /opt/openhost-overleaf/bootstrap_admin.py
RUN chmod 0755 /opt/openhost-overleaf/start.sh \
              /opt/openhost-overleaf/auth_proxy.py \
              /opt/openhost-overleaf/bootstrap_admin.py

# OpenHost-routed port (auth-proxy).  Overleaf's own port (80)
# remains loopback-only.
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-overleaf/start.sh"]
