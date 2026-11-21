BEGIN;

-- =============================================
-- 站内通知权限定义、继承与内置用户组授权
-- notification.* 管理个人站内通知（可被 OAuth 应用申请）；
-- notifications.send 向用户发送通知，notifications.read 搜索全部用户的站内通知。
-- admin 用户组持有 student_id:**，会自动获得新增权限，无需单独授权。
-- =============================================
DO
$$
    DECLARE
        core_app_id BIGINT;
    BEGIN
        SELECT id
        INTO core_app_id
        FROM apps
        WHERE lower(namespace) = 'student_id'
          AND deleted_at IS NULL;

        IF core_app_id IS NULL THEN
            RAISE EXCEPTION '核心应用（namespace=student_id）不存在，无法初始化站内通知权限';
        END IF;

        -- -------------------------------------
        -- 权限定义
        -- -------------------------------------
        INSERT INTO permission_defs (app_id, value, description, requestable)
        VALUES
            (core_app_id, 'notification.read', '查看个人站内通知', true),
            (core_app_id, 'notification.write', '管理个人站内通知（标记已读、删除）', true),
            (core_app_id, 'notifications.send', '向用户发送通知（站内、邮件、QQ）', false),
            (core_app_id, 'notifications.read', '搜索全部用户的站内通知', false)
        ON CONFLICT (app_id, value) DO NOTHING;

        -- -------------------------------------
        -- 权限继承：管理个人通知 → 查看个人通知
        -- -------------------------------------
        INSERT INTO permission_implies (permission_id, implied_permission_id)
        SELECT writer.id, reader.id
        FROM permission_defs writer
                 JOIN permission_defs reader
                      ON reader.app_id = writer.app_id
                          AND reader.value = 'notification.read'
        WHERE writer.app_id = core_app_id
          AND writer.value = 'notification.write'
        ON CONFLICT (permission_id, implied_permission_id) DO NOTHING;

        -- -------------------------------------
        -- 系统普通用户组默认获得个人站内通知权限
        -- -------------------------------------
        INSERT INTO role_permissions (role_id, permission)
        SELECT r.id, 'student_id:notification.*'
        FROM roles r
        WHERE r.app_id = core_app_id
          AND r.name = 'user'
        ON CONFLICT (role_id, permission) DO NOTHING;
    END
$$;

COMMIT;
