BEGIN;

DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP TABLE IF EXISTS oauth_authorizations;
DROP TABLE IF EXISTS user_permission_grants;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permission_implies;
DROP TABLE IF EXISTS permission_defs;
DROP TABLE IF EXISTS apps;
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

DROP TYPE IF EXISTS app_auth_status;
DROP TYPE IF EXISTS app_status;
DROP TYPE IF EXISTS app_type;
DROP TYPE IF EXISTS register_request_status;
DROP TYPE IF EXISTS school;
DROP TYPE IF EXISTS user_type;

COMMIT;
