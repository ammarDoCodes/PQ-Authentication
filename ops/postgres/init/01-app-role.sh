#!/bin/sh
set -eu

: "${QG_APP_PASSWORD:?Set QG_APP_PASSWORD for the development application role}"
: "${QG_MIGRATION_PASSWORD:?Set QG_MIGRATION_PASSWORD for the development migration role}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

psql --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
  \i /roles.sql
SQL
