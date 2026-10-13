.bail on
BEGIN IMMEDIATE;
UPDATE monitor
SET url = 'https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta',
    cache_bust = 0
WHERE id = 20
  AND name = '业务·Gemini'
  AND url IN (
    'https://gemini.google.com/',
    'https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta'
  );
SELECT 'updated=' || changes();
COMMIT;
PRAGMA integrity_check;
