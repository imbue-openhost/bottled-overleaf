#!/bin/bash
# Boot MongoDB + Redis + Overleaf + auth-proxy for OpenHost.
#
# Topology:
#
#   browser → OpenHost router → container :8080 (auth_proxy.py)
#                                     → 127.0.0.1:80 (Overleaf nginx + web)
#                                            ├─ 127.0.0.1:27017 (Mongo)
#                                            └─ 127.0.0.1:6379  (Redis)
#
# First-boot bootstrap:
#   * Init Mongo data dir, start mongod with replica-set name
#     "overleaf" (Overleaf >= 4.0 requires a replica set even
#     when single-node — uses transactions internally).
#   * rs.initiate() if not already initialised.
#   * Start Redis (no auth, loopback only).
#   * Run /sbin/my_init in the background to start Overleaf's
#     own bundled services (web, clsi, document-updater,
#     real-time, etc.).
#   * Wait for Overleaf web to bind :80 + GET /login to succeed.
#   * Run bootstrap_admin.py to mint an admin user.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/overleaf}"
TEMP="${OPENHOST_APP_TEMP_DIR:-/tmp}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-overleaf}"
APP_HOST="${APP_NAME}.${ZONE_DOMAIN}"

OVERLEAF_DATA="$PERSIST/data"
MONGO_DATA="$PERSIST/mongo"
MONGO_LOG_DIR="$PERSIST/mongo-log"
MONGO_LOG="$MONGO_LOG_DIR/mongod.log"
REDIS_DIR="$PERSIST/redis"
CRED_FILE="$PERSIST/admin-credentials.txt"

mkdir -p "$OVERLEAF_DATA" "$MONGO_DATA" "$MONGO_LOG_DIR" "$REDIS_DIR"

# Overleaf's image expects /var/lib/overleaf to be its data root.
# Bind mount $OVERLEAF_DATA there if possible; otherwise symlink.
if ! mountpoint -q /var/lib/overleaf; then
    if mount --bind "$OVERLEAF_DATA" /var/lib/overleaf 2>/dev/null; then
        echo "[start.sh] Bind-mounted $OVERLEAF_DATA -> /var/lib/overleaf"
    else
        # Rootless podman blocks CAP_SYS_ADMIN; symlink instead.
        # We must move the upstream-image-baked-in /var/lib/overleaf
        # contents into our persistent dir (one-time copy on first
        # boot when persistent dir is empty).
        if [[ -d /var/lib/overleaf ]] && [[ ! -e "$OVERLEAF_DATA/.openhost-initialized" ]]; then
            cp -a /var/lib/overleaf/. "$OVERLEAF_DATA/" 2>/dev/null || true
            touch "$OVERLEAF_DATA/.openhost-initialized"
        fi
        rm -rf /var/lib/overleaf
        ln -snf "$OVERLEAF_DATA" /var/lib/overleaf
        echo "[start.sh] Symlinked /var/lib/overleaf -> $OVERLEAF_DATA"
    fi
fi

# -----------------------------------------------------------------
# MongoDB bootstrap
# -----------------------------------------------------------------

chown -R mongodb:mongodb "$MONGO_DATA" "$MONGO_LOG_DIR" 2>/dev/null || true
chmod 0755 "$MONGO_DATA" "$MONGO_LOG_DIR"

# Mongo config: bind localhost only, replica set name "overleaf"
# (Overleaf 4.x uses transactions; replica set required).
cat > /etc/mongod.openhost.conf <<EOF
storage:
  dbPath: $MONGO_DATA
systemLog:
  destination: file
  logAppend: true
  path: $MONGO_LOG
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
replication:
  replSetName: overleaf
EOF

echo "[start.sh] Starting MongoDB on 127.0.0.1:27017"
gosu mongodb mongod --config /etc/mongod.openhost.conf --fork

# Wait for Mongo to accept connections.
for _ in $(seq 1 30); do
    if mongosh --quiet --eval 'db.adminCommand("ping")' >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Initialise the replica set on first boot.  Idempotent: if it's
# already initialised, the command no-ops.
RS_STATUS="$(mongosh --quiet --eval 'try { rs.status().ok } catch (e) { 0 }' 2>/dev/null || echo 0)"
if [[ "$RS_STATUS" != "1" ]]; then
    echo "[start.sh] Initialising mongodb replica set"
    mongosh --quiet --eval 'rs.initiate({ _id: "overleaf", members: [{ _id: 0, host: "127.0.0.1:27017" }] })' \
        | sed 's/^/[mongo-rs.initiate] /'
    # Wait for the replica set to elect a primary.
    for _ in $(seq 1 20); do
        if mongosh --quiet --eval 'rs.status().myState == 1' 2>/dev/null | grep -q true; then
            break
        fi
        sleep 1
    done
fi

# Overleaf's check-mongodb.mjs verifies featureCompatibilityVersion
# against MIN_MONGO_FEATURE_COMPATIBILITY_VERSION (currently 6.0).
# A fresh Mongo 6.0 install defaults to FCV 6.0 already, but on a
# Mongo 7.0 install it defaults to FCV 7.0 which the check
# accepts.  Idempotent set just to be safe.
mongosh --quiet --eval 'db.adminCommand({ setFeatureCompatibilityVersion: "6.0", confirm: true })' 2>/dev/null \
    | sed 's/^/[mongo-fcv] /' || true

# Also tell Overleaf's checks to be lenient if they fail (e.g.
# because the admin DB is restricted).  We're a single-tenant
# deployment with trust auth, so there's no security loss.
export ALLOW_MONGO_ADMIN_CHECK_FAILURES=true

# -----------------------------------------------------------------
# Redis bootstrap
# -----------------------------------------------------------------

mkdir -p "$REDIS_DIR"
chown -R redis:redis "$REDIS_DIR" 2>/dev/null || chown -R nobody:nogroup "$REDIS_DIR" 2>/dev/null || true

echo "[start.sh] Starting Redis on 127.0.0.1:6379"
if id redis >/dev/null 2>&1; then
    REDIS_USER=redis
else
    REDIS_USER=nobody
fi
gosu "$REDIS_USER" redis-server --bind 127.0.0.1 --port 6379 --dir "$REDIS_DIR" \
    --save "" --appendonly no --daemonize yes \
    --pidfile "$REDIS_DIR/redis.pid" --logfile "$REDIS_DIR/redis.log"

for _ in $(seq 1 10); do
    if redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Overleaf env config
# -----------------------------------------------------------------

# The upstream image reads OVERLEAF_* and a few legacy SHARELATEX_*
# env vars at startup.  Point Mongo + Redis at our loopback
# instances.
export OVERLEAF_APP_NAME="OpenHost ($APP_HOST)"
export OVERLEAF_MONGO_URL="mongodb://127.0.0.1:27017/sharelatex"
export OVERLEAF_REDIS_HOST=127.0.0.1
export REDIS_HOST=127.0.0.1
export OVERLEAF_SITE_URL="https://$APP_HOST"
export OVERLEAF_NAV_TITLE="OpenHost Overleaf"
# Sandboxed compiles need a separate docker-in-docker which we
# don't provide; disable.
export SANDBOXED_COMPILES=false
export DOCKER_RUNNER=false
# Email confirmation flow needs SMTP; we don't have it.  Disable.
export EMAIL_CONFIRMATION_DISABLED=true
# Don't auto-tell upstream we exist.
export OVERLEAF_TELEMETRY_DISABLED=true

# -----------------------------------------------------------------
# Launch Overleaf via the upstream /sbin/my_init
# -----------------------------------------------------------------
#
# /sbin/my_init is Phusion's init replacement.  It runs all
# scripts in /etc/my_init.d in order then starts services
# defined in /etc/service/.  Our bootstrap_admin.py runs after
# my_init has had a chance to bring up the web service.

echo "[start.sh] Starting Overleaf services via /sbin/my_init"
/sbin/my_init &
MYINIT_PID=$!

# -----------------------------------------------------------------
# Launch auth-proxy IMMEDIATELY so OpenHost's healthcheck on
# /_healthz starts succeeding as soon as the proxy is up.
# -----------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:80"
export AUTH_PROXY_LISTEN_PORT="8080"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="80"
export AUTH_PROXY_CRED_FILE="$CRED_FILE"
python3 /opt/openhost-overleaf/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Bootstrap admin (runs once; no-op on subsequent boots).
# Background it so it doesn't block the proxy from accepting
# the OpenHost healthcheck.
# -----------------------------------------------------------------

(
    CRED_FILE="$CRED_FILE" \
    OPENHOST_ZONE_DOMAIN="$ZONE_DOMAIN" \
    OVERLEAF_WEB_PORT=80 \
    python3 /opt/openhost-overleaf/bootstrap_admin.py 2>&1 \
    | sed 's/^/[bootstrap] /'
) &

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------

trap 'kill -TERM "$MYINIT_PID" "$PROXY_PID" 2>/dev/null; mongosh --quiet --eval "db.shutdownServer()" 2>/dev/null; wait' TERM INT

set +e
wait -n "$MYINIT_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$MYINIT_PID" "$PROXY_PID" 2>/dev/null || true
mongosh --quiet --eval 'db.shutdownServer()' 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
