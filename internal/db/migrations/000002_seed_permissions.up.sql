BEGIN;

-- =============================================
-- 核心应用权限定义、权限继承、内置用户组与权限模式种子
-- =============================================
DO
$$
    DECLARE
        core_app_id      BIGINT;
        admin_user_id    BIGINT;
        user_role_id     BIGINT;
        reviewer_role_id BIGINT;
        admin_role_id    BIGINT;
    BEGIN
        SELECT id
        INTO core_app_id
        FROM apps
        WHERE lower(namespace) = 'student_id'
          AND deleted_at IS NULL;

        IF core_app_id IS NULL THEN
            RAISE EXCEPTION '核心应用（namespace=student_id）不存在，无法初始化权限种子';
        END IF;

        SELECT id
        INTO admin_user_id
        FROM users
        WHERE lower(username) = 'admin'
          AND deleted_at IS NULL
        ORDER BY id
        LIMIT 1;

        IF admin_user_id IS NULL THEN
            RAISE EXCEPTION '内置管理员（username=admin）不存在，无法初始化权限种子';
        END IF;

        -- -------------------------------------
        -- 权限定义
        -- -------------------------------------
        INSERT INTO permission_defs (app_id, value, description, requestable)
        VALUES
            -- 注册申请
            (core_app_id, 'register_requests.list', '查看注册申请列表', false),
            (core_app_id, 'register_requests.read', '查看注册申请详情', false),
            (core_app_id, 'register_requests.review', '审核注册申请', false),
            -- 用户
            (core_app_id, 'users.list', '搜索全部用户', false),
            (core_app_id, 'users.delete', '删除用户', false),
            -- 自己的资料
            (core_app_id, 'user.profile.read.basic', '读取个人基础资料', true),
            (core_app_id, 'user.profile.read.identity', '读取个人身份信息', true),
            (core_app_id, 'user.profile.read.real_name', '读取个人真实姓名', true),
            (core_app_id, 'user.profile.read.about', '读取个人简介与签名', true),
            (core_app_id, 'user.profile.read.visibilities', '读取个人资料可见性', true),
            (core_app_id, 'user.profile.update.basic', '修改个人基础资料', true),
            (core_app_id, 'user.profile.update.about', '修改个人简介与签名', true),
            (core_app_id, 'user.profile.update.visibilities', '修改个人资料可见性', true),
            -- 他人资料
            (core_app_id, 'users.profile.read.basic', '读取他人基础资料', false),
            (core_app_id, 'users.profile.read.identity', '读取他人身份信息', false),
            (core_app_id, 'users.profile.read.real_name.allowed', '按可见性读取他人真实姓名', false),
            (core_app_id, 'users.profile.read.real_name', '无视可见性读取他人真实姓名', false),
            (core_app_id, 'users.profile.read.about', '读取他人简介与签名', false),
            (core_app_id, 'users.profile.read.visibilities', '读取他人资料可见性', false),
            (core_app_id, 'users.profile.update.basic', '修改他人基础资料', false),
            (core_app_id, 'users.profile.update.identity', '修改他人身份信息', false),
            (core_app_id, 'users.profile.update.about', '修改他人简介与签名', false),
            (core_app_id, 'users.profile.update.visibilities', '修改他人资料可见性', false),
            -- 用户封禁
            (core_app_id, 'user.ban.read', '查看个人封禁信息', true),
            (core_app_id, 'users.ban.read', '查看他人封禁信息', false),
            (core_app_id, 'users.ban.write', '封禁或解封用户', false),
            -- 用户会话
            (core_app_id, 'user.session.read', '查看个人登录会话', false),
            (core_app_id, 'user.session.write', '管理个人登录会话', false),
            (core_app_id, 'users.session.read', '查看他人登录会话', false),
            (core_app_id, 'users.session.write', '管理他人登录会话', false),
            -- 用户关注
            (core_app_id, 'user.relation.read', '查看个人关注关系', true),
            (core_app_id, 'user.relation.write', '管理个人关注关系', true),
            (core_app_id, 'users.relation.read', '查看他人关注关系（不受可见性限制）', false),
            (core_app_id, 'users.relation.read.allowed', '按可见性查看他人关注关系', false),
            (core_app_id, 'users.relation.write', '管理他人关注关系', false),
            -- 权限管理
            (core_app_id, 'permission.read', '读取拥有的应用权限定义', false),
            (core_app_id, 'permission.write', '管理拥有的应用权限定义', false),
            (core_app_id, 'permissions.read', '读取全部权限定义', false),
            (core_app_id, 'permissions.write', '管理全部权限定义', false),
            -- 应用管理
            (core_app_id, 'app.read', '读取拥有的应用信息', false),
            (core_app_id, 'app.update', '修改拥有的应用信息', false),
            (core_app_id, 'app.delete', '删除拥有的应用', false),
            (core_app_id, 'apps.list', '查看全部应用', false),
            (core_app_id, 'apps.create', '创建应用', false),
            (core_app_id, 'apps.update', '修改全部应用', false),
            (core_app_id, 'apps.suspend', '停用或启用应用', false),
            (core_app_id, 'apps.delete', '删除全部应用', false),
            -- OAuth 授权管理
            (core_app_id, 'oauth.read', '查看个人 OAuth 授权', false),
            (core_app_id, 'oauth.revoke', '撤销个人 OAuth 授权', false),
            (core_app_id, 'oauths.read', '查看他人 OAuth 授权', false),
            (core_app_id, 'oauths.revoke', '撤销他人 OAuth 授权', false)
        ON CONFLICT (app_id, value) DO NOTHING;

        -- -------------------------------------
        -- 权限继承
        -- 只写入直接边，传递闭包由运行时展开。
        -- -------------------------------------
        INSERT INTO permission_implies (permission_id, implied_permission_id)
        SELECT def.id, implied_def.id
        FROM (
                 -- list → read
                 SELECT pd.value                                     AS permission,
                        regexp_replace(pd.value, '\.list$', '.read') AS implied
                 FROM permission_defs pd
                 WHERE pd.app_id = core_app_id
                   AND pd.value ~ '\.list$'

                 UNION

                 -- 写操作 → list
                 SELECT pd.value,
                        regexp_replace(pd.value, '\.(write|update|delete|review|suspend|revoke)(\..+)?$', '.list\2')
                 FROM permission_defs pd
                 WHERE pd.app_id = core_app_id
                   AND pd.value ~ '\.(write|update|delete|review|suspend|revoke)(\..+)?$'

                 UNION

                 -- 写操作 → read
                 SELECT pd.value,
                        regexp_replace(pd.value, '\.(write|update|delete|review|suspend|revoke)(\..+)?$', '.read\2')
                 FROM permission_defs pd
                 WHERE pd.app_id = core_app_id
                   AND pd.value ~ '\.(write|update|delete|review|suspend|revoke)(\..+)?$'

                 UNION

                 -- 他人 → 个人
                 SELECT pd.value,
                        CASE
                            WHEN pd.value LIKE 'users.%'
                                THEN 'user.' || substring(pd.value FROM 7)
                            ELSE 'oauth.' || substring(pd.value FROM 8)
                            END
                 FROM permission_defs pd
                 WHERE pd.app_id = core_app_id
                   AND (pd.value LIKE 'users.%' OR pd.value LIKE 'oauths.%')) AS pairs
                 JOIN permission_defs def
                      ON def.app_id = core_app_id AND def.value = pairs.permission
                 JOIN permission_defs implied_def
                      ON implied_def.app_id = core_app_id AND implied_def.value = pairs.implied
        ON CONFLICT (permission_id, implied_permission_id) DO NOTHING;

        -- -------------------------------------
        -- 内置用户组
        -- student / teacher / user 为系统用户组：创建用户时自动分配，不允许删改。
        -- -------------------------------------
        INSERT INTO roles (app_id, name, note, is_system)
        VALUES (core_app_id, 'student', '学生基础用户组（系统）', true),
               (core_app_id, 'teacher', '教师基础用户组（系统）', true),
               (core_app_id, 'user', '普通用户组（系统）', true),
               (core_app_id, 'reviewer', '注册申请审核员', false),
               (core_app_id, 'admin', '平台管理员', false)
        ON CONFLICT (app_id, name) DO NOTHING;

        -- 兼容已有用户组：系统用户组始终标记为 is_system。
        UPDATE roles
        SET is_system = true
        WHERE app_id = core_app_id
          AND name IN ('student', 'teacher', 'user');

        SELECT id INTO user_role_id FROM roles WHERE app_id = core_app_id AND name = 'user';
        SELECT id INTO reviewer_role_id FROM roles WHERE app_id = core_app_id AND name = 'reviewer';
        SELECT id INTO admin_role_id FROM roles WHERE app_id = core_app_id AND name = 'admin';

        IF user_role_id IS NULL OR reviewer_role_id IS NULL OR admin_role_id IS NULL THEN
            RAISE EXCEPTION '内置用户组创建失败';
        END IF;

        -- -------------------------------------
        -- 普通用户组：查看他人 + 修改自己
        -- -------------------------------------
        INSERT INTO role_permissions (role_id, permission)
        VALUES
            -- 个人权限：资料读取/修改、关注、会话、封禁信息
            (user_role_id, 'student_id:user.**'),
            -- 查看他人：用户搜索与按可见性放行的资料/关注关系
            (user_role_id, 'student_id:users.list'),
            (user_role_id, 'student_id:users.profile.read.basic'),
            (user_role_id, 'student_id:users.profile.read.identity'),
            (user_role_id, 'student_id:users.profile.read.real_name.allowed'),
            (user_role_id, 'student_id:users.profile.read.about'),
            (user_role_id, 'student_id:users.profile.read.visibilities'),
            (user_role_id, 'student_id:users.relation.read.allowed'),
            -- 个人 OAuth 授权与名下应用管理
            (user_role_id, 'student_id:oauth.*'),
            (user_role_id, 'student_id:app.*')
        ON CONFLICT (role_id, permission) DO NOTHING;

        -- -------------------------------------
        -- 审核员用户组：普通用户组 + 注册申请审核
        -- -------------------------------------
        INSERT INTO role_permissions (role_id, permission)
        SELECT reviewer_role_id, permission
        FROM role_permissions
        WHERE role_id = user_role_id
        ON CONFLICT (role_id, permission) DO NOTHING;

        INSERT INTO role_permissions (role_id, permission)
        VALUES (reviewer_role_id, 'student_id:register_requests.*')
        ON CONFLICT (role_id, permission) DO NOTHING;

        -- -------------------------------------
        -- 管理员用户组：命名空间下全部权限（含后续新增）
        -- -------------------------------------
        INSERT INTO role_permissions (role_id, permission)
        VALUES (admin_role_id, 'student_id:**')
        ON CONFLICT (role_id, permission) DO NOTHING;

        -- -------------------------------------
        -- 内置管理员的用户组：教师 + 普通用户 + 管理员
        -- -------------------------------------
        INSERT INTO user_roles (user_id, role_id, granted_by)
        SELECT admin_user_id, r.id, NULL
        FROM roles r
        WHERE r.app_id = core_app_id
          AND r.name IN ('teacher', 'user', 'admin')
        ON CONFLICT (user_id, role_id) DO NOTHING;
    END
$$;

COMMIT;
