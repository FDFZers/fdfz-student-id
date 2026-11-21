BEGIN;

-- =============================================
-- 用户登录二次验证开关
-- 关闭后登录只需密码；修改密码、绑定方式、会话管理等敏感操作仍要求二次验证。
-- 默认 TRUE，保持既有「绑定即校验」的行为。
-- =============================================
ALTER TABLE users
    ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT TRUE;

COMMIT;
