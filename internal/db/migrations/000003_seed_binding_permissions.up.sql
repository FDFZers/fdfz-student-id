BEGIN;

-- =============================================
-- 绑定信息权限定义、继承与内置用户组授权
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
            RAISE EXCEPTION '核心应用（namespace=student_id）不存在，无法初始化绑定权限';
        END IF;

        -- -------------------------------------
        -- 权限定义
        -- binding.* 读取自己（可被 OAuth 应用申请），bindings.* 读取他人或管理他人绑定
        -- -------------------------------------
        INSERT INTO permission_defs (app_id, value, description, requestable)
        VALUES
            (core_app_id, 'binding.read.status', '读取个人绑定状态', true),
            (core_app_id, 'binding.read.email', '读取个人绑定邮箱', true),
            (core_app_id, 'binding.read.qq', '读取个人绑定 QQ', true),
            (core_app_id, 'bindings.read.status', '读取他人绑定状态', false),
            (core_app_id, 'bindings.read.email', '读取他人绑定邮箱', false),
            (core_app_id, 'bindings.read.qq', '读取他人绑定 QQ', false),
            (core_app_id, 'bindings.write', '设置或删除他人绑定', false)
        ON CONFLICT (app_id, value) DO NOTHING;

        -- -------------------------------------
        -- 权限继承
        -- 读取他人 → 读取自己
        -- -------------------------------------
        INSERT INTO permission_implies (permission_id, implied_permission_id)
        SELECT def.id, implied.id
        FROM permission_defs def
                 JOIN permission_defs implied
                      ON implied.app_id = def.app_id
                          AND implied.value = regexp_replace(def.value, '^bindings\.', 'binding.')
        WHERE def.app_id = core_app_id
          AND def.value LIKE 'bindings.read.%'
        ON CONFLICT (permission_id, implied_permission_id) DO NOTHING;

        -- 管理绑定 → 读取他人的三类绑定状态
        INSERT INTO permission_implies (permission_id, implied_permission_id)
        SELECT writer.id, reader.id
        FROM permission_defs writer
                 JOIN permission_defs reader
                      ON reader.app_id = writer.app_id
                          AND reader.value LIKE 'bindings.read.%'
        WHERE writer.app_id = core_app_id
          AND writer.value = 'bindings.write'
        ON CONFLICT (permission_id, implied_permission_id) DO NOTHING;

        -- -------------------------------------
        -- 内置用户组：普通用户与审核员可读取自己的绑定信息
        -- -------------------------------------
        INSERT INTO role_permissions (role_id, permission)
        SELECT r.id, 'student_id:binding.*'
        FROM roles r
        WHERE r.app_id = core_app_id
          AND r.name IN ('user', 'reviewer')
        ON CONFLICT (role_id, permission) DO NOTHING;
    END
$$;

COMMIT;
