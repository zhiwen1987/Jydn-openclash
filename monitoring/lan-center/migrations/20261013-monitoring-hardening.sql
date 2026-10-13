.bail on
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

CREATE TEMP TABLE _single_match(value INTEGER NOT NULL CHECK(value = 1));
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = 'OpenClash 分流验收';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = 'DNS·国内域名';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = 'DNS·海外域名';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = '业务·AMD中国·TokenFactory';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = '业务·涂鸦中国';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = '业务·ChatGPT';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name = '业务·Gemini';
DELETE FROM _single_match;
INSERT INTO _single_match SELECT count(*) FROM monitor WHERE name IN ('业务·Google 204', '业务·Google策略组');
DROP TABLE _single_match;

UPDATE monitor
SET cache_bust = 0,
    description = '父分组；异常通知写入本地告警日志，可选转发外部 Webhook。'
WHERE name = 'OpenClash 分流验收';

UPDATE monitor
SET timeout = 5,
    cache_bust = 0
WHERE name IN ('DNS·国内域名', 'DNS·海外域名');

UPDATE monitor
SET timeout = 15,
    cache_bust = 0
WHERE name IN ('业务·AMD中国·TokenFactory', '业务·涂鸦中国');

UPDATE monitor
SET url = 'http://failover:8080/probe/chatgpt',
    accepted_statuscodes_json = '["204"]',
    timeout = 15,
    cache_bust = 0,
    description = '通过 OpenClash 对 Codex 后端执行真实 POST，仅 JSON 400/401 视为业务可达。'
WHERE name = '业务·ChatGPT';

UPDATE monitor
SET url = 'http://failover:8080/probe/gemini',
    accepted_statuscodes_json = '["204"]',
    timeout = 15,
    cache_bust = 0,
    description = '经 OpenClash 规则访问 Gemini Discovery API，验证真实业务出口。'
WHERE name = '业务·Gemini';

UPDATE monitor
SET name = '业务·Google策略组',
    url = 'http://failover:8080/probe/google',
    accepted_statuscodes_json = '["204"]',
    timeout = 15,
    cache_bust = 0,
    description = '经 OpenClash 规则访问 Google 204，验证真实策略出口，不再误测手动选择组。'
WHERE name IN ('业务·Google 204', '业务·Google策略组');

INSERT INTO monitor (
  name, active, user_id, interval, url, type, maxretries, retry_interval,
  accepted_statuscodes_json, timeout, cache_bust, parent, description
)
SELECT
  '链路·实际海外出口', 1, parent_group.user_id, 30,
  'https://www.gstatic.com/generate_204', 'http', 2, 10,
  '["204"]', 15, 0, parent_group.id,
  '从独立监控主机验证实际默认海外出口，与 OpenClash 策略组探测相互补充。'
FROM monitor AS parent_group
WHERE parent_group.name = 'OpenClash 分流验收'
  AND NOT EXISTS (SELECT 1 FROM monitor WHERE name = '链路·实际海外出口');

UPDATE monitor
SET active = 1,
    interval = 30,
    url = 'https://www.gstatic.com/generate_204',
    type = 'http',
    maxretries = 2,
    retry_interval = 10,
    accepted_statuscodes_json = '["204"]',
    timeout = 15,
    cache_bust = 0,
    parent = (SELECT id FROM monitor WHERE name = 'OpenClash 分流验收'),
    description = '从独立监控主机验证实际默认海外出口，与 OpenClash 策略组探测相互补充。'
WHERE name = '链路·实际海外出口';

INSERT INTO notification(name, active, user_id, is_default, config)
SELECT
  'lan-center 本地告警', 1, parent_group.user_id, 0,
  '{"type":"webhook","webhookURL":"http://failover:8080/alert","webhookContentType":"json","httpMethod":"POST","webhookAdditionalHeaders":""}'
FROM monitor AS parent_group
WHERE parent_group.name = 'OpenClash 分流验收'
  AND NOT EXISTS (SELECT 1 FROM notification WHERE name = 'lan-center 本地告警');

UPDATE notification
SET active = 1,
    config = '{"type":"webhook","webhookURL":"http://failover:8080/alert","webhookContentType":"json","httpMethod":"POST","webhookAdditionalHeaders":""}'
WHERE name = 'lan-center 本地告警';

INSERT INTO monitor_notification(id, monitor_id, notification_id)
SELECT
  COALESCE((SELECT max(id) FROM monitor_notification), 0) + 1,
  parent_group.id,
  local_notification.id
FROM monitor AS parent_group
JOIN notification AS local_notification ON local_notification.name = 'lan-center 本地告警'
WHERE parent_group.name = 'OpenClash 分流验收'
  AND NOT EXISTS (
    SELECT 1 FROM monitor_notification
    WHERE monitor_id = parent_group.id AND notification_id = local_notification.id
  );

COMMIT;
PRAGMA integrity_check;
