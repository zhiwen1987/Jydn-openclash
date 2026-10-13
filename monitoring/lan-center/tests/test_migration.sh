#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
database="$(mktemp)"
trap 'rm -f "$database"' EXIT

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
CREATE TABLE monitor (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name TEXT,
  active BOOLEAN NOT NULL DEFAULT 1,
  user_id INTEGER,
  interval INTEGER NOT NULL DEFAULT 20,
  url TEXT,
  type TEXT,
  maxretries INTEGER NOT NULL DEFAULT 0,
  accepted_statuscodes_json TEXT NOT NULL DEFAULT '["200-299"]',
  retry_interval INTEGER NOT NULL DEFAULT 0,
  description TEXT,
  parent INTEGER REFERENCES monitor(id),
  timeout DOUBLE NOT NULL DEFAULT 0,
  cache_bust BOOLEAN NOT NULL DEFAULT 0
);
CREATE TABLE notification (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name TEXT,
  active BOOLEAN NOT NULL DEFAULT 1,
  user_id INTEGER NOT NULL,
  is_default BOOLEAN NOT NULL DEFAULT 0,
  config TEXT
);
CREATE TABLE monitor_notification (
  id INTEGER PRIMARY KEY NOT NULL,
  monitor_id INTEGER NOT NULL REFERENCES monitor(id),
  notification_id INTEGER NOT NULL REFERENCES notification(id)
);
INSERT INTO monitor(id,name,user_id,type,url,parent) VALUES
  (14,'OpenClash 分流验收',1,'group','https://',NULL),
  (15,'DNS·国内域名',1,'dns','https://',14),
  (16,'DNS·海外域名',1,'dns','https://',14),
  (17,'业务·AMD中国·TokenFactory',1,'http','https://developer.amd.com.cn/radeon/tokenfactory',14),
  (18,'业务·涂鸦中国',1,'http','https://www.tuya.com/cn/',14),
  (19,'业务·ChatGPT',1,'http','https://chatgpt.com/cdn-cgi/trace',14),
  (20,'业务·Gemini',1,'http','https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta',14),
  (21,'业务·Google 204',1,'http','https://www.gstatic.com/generate_204',14);
SQL

sqlite3 "$database" < "$root/migrations/20261013-monitoring-hardening.sql"
sqlite3 "$database" < "$root/migrations/20261013-monitoring-hardening.sql"

test "$(sqlite3 "$database" "select count(*) from monitor where name='链路·实际海外出口';")" = 1
test "$(sqlite3 "$database" "select count(*) from notification where name='lan-center 本地告警';")" = 1
test "$(sqlite3 "$database" "select count(*) from monitor_notification;")" = 1
test "$(sqlite3 "$database" "select count(*) from monitor where parent=14;")" = 8
test "$(sqlite3 "$database" "select count(*) from monitor where name in ('业务·ChatGPT','业务·Gemini','业务·Google策略组') and url like 'http://failover:8080/probe/%' and timeout=15 and cache_bust=0;")" = 3
test "$(sqlite3 "$database" 'pragma integrity_check;')" = ok

echo 'monitoring migration test: ok'
