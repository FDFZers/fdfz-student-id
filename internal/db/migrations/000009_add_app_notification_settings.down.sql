BEGIN;

ALTER TABLE oauth_authorizations
    DROP COLUMN allow_notifications;

ALTER TABLE users
    DROP COLUMN app_notifications_enabled;

COMMIT;
