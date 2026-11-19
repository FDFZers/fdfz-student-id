BEGIN;

-- 删除 000003 写入的绑定权限定义、继承与内置用户组授权。
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
          AND permission = 'student_id:binding.*';

        DELETE FROM user_permission_grants
        WHERE permission IN (
            'student_id:binding.read.status',
            'student_id:binding.read.email',
            'student_id:binding.read.qq',
            'student_id:bindings.read.status',
            'student_id:bindings.read.email',
            'student_id:bindings.read.qq',
            'student_id:bindings.write'
        );

        -- permission_implies 通过外键级联删除
        DELETE FROM permission_defs
        WHERE app_id = core_app_id
          AND value IN (
            'binding.read.status',
            'binding.read.email',
            'binding.read.qq',
            'bindings.read.status',
            'bindings.read.email',
            'bindings.read.qq',
            'bindings.write'
        );
    END
$$;

COMMIT;
