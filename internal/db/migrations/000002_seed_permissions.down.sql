BEGIN;

-- 删除 000002 写入的核心应用权限定义与内置用户组。
-- 内置管理员与应用本身由 000001 管理，这里不删除。
DELETE FROM roles
WHERE app_id IN (SELECT id FROM apps WHERE lower(namespace) = 'student_id' AND deleted_at IS NULL);

-- 授权表只存权限串文本、无外键，需在删除权限定义前清理。
DELETE FROM user_permission_grants
WHERE split_part(permission, ':', 1) = 'student_id';

UPDATE oauth_authorizations
SET permissions = COALESCE(
    (
        SELECT array_agg(p)
        FROM unnest(permissions) AS t(p)
        WHERE split_part(p, ':', 1) <> 'student_id'
    ),
    '{}'
)
WHERE EXISTS (
    SELECT 1 FROM unnest(permissions) AS t(p)
    WHERE split_part(p, ':', 1) = 'student_id'
);

DELETE FROM permission_defs
WHERE app_id IN (SELECT id FROM apps WHERE lower(namespace) = 'student_id' AND deleted_at IS NULL);

COMMIT;
