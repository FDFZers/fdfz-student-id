BEGIN;

-- =============================================
-- 用户管理权限定义
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
            RAISE EXCEPTION '核心应用（namespace=student_id）不存在，无法初始化用户管理权限';
        END IF;

        -- -------------------------------------
        -- 权限定义
        -- -------------------------------------
        INSERT INTO permission_defs (app_id, value, description, requestable)
        VALUES
            (core_app_id, 'users.create', '创建用户', false),
            (core_app_id, 'users.password.write', '重置他人密码', false)
        ON CONFLICT (app_id, value) DO NOTHING;

        -- -------------------------------------
        -- 权限继承：创建用户与重置密码都需要定位用户，继承用户搜索能力。
        -- -------------------------------------
        INSERT INTO permission_implies (permission_id, implied_permission_id)
        SELECT def.id, implied.id
        FROM permission_defs def
                 JOIN permission_defs implied
                      ON implied.app_id = def.app_id
                          AND implied.value = 'users.list'
        WHERE def.app_id = core_app_id
          AND def.value IN ('users.create', 'users.password.write')
        ON CONFLICT (permission_id, implied_permission_id) DO NOTHING;
    END
$$;

COMMIT;
