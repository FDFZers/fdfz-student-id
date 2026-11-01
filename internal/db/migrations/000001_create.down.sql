BEGIN;

DROP TABLE IF EXISTS user_oauth_apps;
DROP TABLE IF EXISTS user_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS oauth_apps;
DROP TABLE IF EXISTS register_requests;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_totp;
DROP TABLE IF EXISTS user_qqs;
DROP TABLE IF EXISTS user_emails;
DROP TABLE IF EXISTS user_passwords;
DROP TABLE IF EXISTS user_follows;
DROP TABLE IF EXISTS user_bans;
DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS fn_update_timestamp();

DROP TYPE IF EXISTS register_request_status;
DROP TYPE IF EXISTS oauth_client_type;
DROP TYPE IF EXISTS school;
DROP TYPE IF EXISTS user_type;

COMMIT;
