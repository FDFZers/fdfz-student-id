BEGIN;

-- =============================================
-- 应用通知设置
--   users.app_notifications_enabled：用户级总开关，关闭后任何应用都不能再向其发送通知；
--   oauth_authorizations.allow_notifications：授权时用户是否允许该应用发送通知。
-- 既有授权默认 FALSE，需要用户重新确认后才允许应用发送通知。
-- =============================================
ALTER TABLE users
    ADD COLUMN app_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE oauth_authorizations
    ADD COLUMN allow_notifications BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
