BEGIN;

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
            RETURN;
        END IF;

        -- 撤销系统用户组的个人通知权限
        DELETE
        FROM role_permissions rp
            USING roles r
        WHERE rp.role_id = r.id
          AND r.app_id = core_app_id
          AND r.name = 'user'
          AND rp.permission = 'student_id:notification.*';

        -- 删除权限继承边（permission_implies 对 permission_defs 有外键级联删除，这里显式清理）
        DELETE
        FROM permission_implies pi
            USING permission_defs def
        WHERE pi.permission_id = def.id
          AND def.app_id = core_app_id
          AND def.value = 'notification.write';

        DELETE
        FROM permission_defs
        WHERE app_id = core_app_id
          AND value IN ('notification.read', 'notification.write', 'notifications.send', 'notifications.read');
    END
$$;

COMMIT;
