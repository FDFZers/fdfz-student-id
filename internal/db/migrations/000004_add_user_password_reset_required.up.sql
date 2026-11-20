BEGIN;

-- =============================================
-- 用户密码重设标记
-- 管理员创建账号或重置密码后置为 true，用户自行修改密码后清除。
-- =============================================
ALTER TABLE users
    ADD COLUMN password_reset_required BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
