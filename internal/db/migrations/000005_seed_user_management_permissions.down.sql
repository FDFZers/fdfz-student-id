BEGIN;

-- 删除 000005 写入的用户管理权限定义、继承与授权。
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

        DELETE FROM role_permissions
        WHERE role_id IN (SELECT id FROM roles WHERE app_id = core_app_id)
          AND permission IN ('student_id:users.create', 'student_id:users.password.write');

        DELETE FROM user_permission_grants
        WHERE permission IN ('student_id:users.create', 'student_id:users.password.write');

        -- OAuth 授权记录只存权限串，需要先剔除即将删除的权限。
        UPDATE oauth_authorizations
        SET permissions = COALESCE(
            (
                SELECT array_agg(p)
                FROM unnest(permissions) AS t(p)
                WHERE p NOT IN ('student_id:users.create', 'student_id:users.password.write')
            ),
            '{}'
        )
        WHERE EXISTS (
            SELECT 1
            FROM unnest(permissions) AS t(p)
            WHERE p IN ('student_id:users.create', 'student_id:users.password.write')
        );

        -- permission_implies 通过外键级联删除
        DELETE FROM permission_defs
        WHERE app_id = core_app_id
          AND value IN ('users.create', 'users.password.write');
    END
$$;

COMMIT;
