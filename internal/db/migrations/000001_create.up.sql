BEGIN;

-- =============================================
-- 枚举类型定义
-- =============================================
CREATE TYPE user_type AS ENUM ('student', 'teacher');
CREATE TYPE school AS ENUM ('fdfz', 'ffxh', 'ffqp', 'ffpd', 'ffja');
CREATE TYPE register_request_status AS ENUM ('pending', 'approved', 'rejected');

CREATE TYPE app_type AS ENUM ('confidential', 'public', 'confidential_device', 'public_device');
CREATE TYPE app_status AS ENUM ('active', 'suspended');
CREATE TYPE app_auth_status AS ENUM ('active', 'update_suspended');

-- =============================================
-- 通用 updated_at 触发器函数
-- =============================================
CREATE OR REPLACE FUNCTION fn_update_timestamp()
    RETURNS TRIGGER AS
$$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        NEW.updated_at = now();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =============================================
-- 用户主表 users
-- =============================================
CREATE TABLE users
(
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username              VARCHAR(32)  NOT NULL,

    type                  user_type    NOT NULL DEFAULT 'student',
    student_num           VARCHAR(16)           DEFAULT NULL,
    real_name             VARCHAR(32)  NOT NULL,
    school                school       NOT NULL DEFAULT 'fdfz',

    nickname              VARCHAR(32)           DEFAULT NULL,
    signature             VARCHAR(128) NOT NULL DEFAULT '',
    bio                   TEXT         NOT NULL DEFAULT '',

    visibilities          JSONB        NOT NULL DEFAULT '{"real_name":"private","followers":"private","following":"private"}',

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ           DEFAULT NULL,
    deletion_scheduled_at TIMESTAMPTZ           DEFAULT NULL,

    CONSTRAINT chk_users_student_num
        CHECK ((type = 'student' AND student_num IS NOT NULL) OR (type <> 'student' AND student_num IS NULL))
);

CREATE UNIQUE INDEX uq_users_username_lower_active
    ON users (lower(username))
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_school_student_num_active
    ON users (school, student_num)
    WHERE type = 'student' AND deleted_at IS NULL;

CREATE INDEX idx_users_student_num
    ON users (student_num);
CREATE INDEX idx_users_type_active
    ON users (type)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_users_school_active
    ON users (school)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at
    ON users (created_at);
CREATE INDEX idx_users_updated_at
    ON users (updated_at);
CREATE INDEX idx_users_deleted_at
    ON users (deleted_at);
CREATE INDEX idx_users_deletion_scheduled
    ON users (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL AND deleted_at IS NULL;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE
    ON users
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户封禁 user_bans
-- =============================================
CREATE TABLE user_bans
(
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    reason     VARCHAR(256) NOT NULL,
    end_time   TIMESTAMPTZ           DEFAULT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    enabled    BOOLEAN      NOT NULL DEFAULT true
);

CREATE UNIQUE INDEX uq_user_bans_user_id_active
    ON user_bans (user_id)
    WHERE enabled = true;
CREATE INDEX idx_user_bans_user_id
    ON user_bans (user_id);
CREATE INDEX idx_user_bans_enabled_end_time
    ON user_bans (enabled, end_time);

-- =============================================
-- 用户关注关系 user_follows
-- =============================================
CREATE TABLE user_follows
(
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    follower_id  BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    following_id BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_user_follows_follower_following UNIQUE (follower_id, following_id),
    CONSTRAINT chk_user_follows_not_self CHECK (follower_id <> following_id)
);

CREATE INDEX idx_user_follows_following_id
    ON user_follows (following_id);
CREATE INDEX idx_user_follows_created_at
    ON user_follows (created_at);

-- =============================================
-- 用户密码 user_passwords
-- =============================================
CREATE TABLE user_passwords
(
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    password   VARCHAR(256) NOT NULL, -- argon2id
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_user_passwords PRIMARY KEY (user_id)
);

CREATE TRIGGER trg_user_passwords_updated_at
    BEFORE UPDATE
    ON user_passwords
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户邮箱 user_emails
-- =============================================
CREATE TABLE user_emails
(
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    email      VARCHAR(256) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ           DEFAULT NULL
);

CREATE INDEX idx_user_emails_user_id
    ON user_emails (user_id);
CREATE UNIQUE INDEX uq_user_emails_user_id_active
    ON user_emails (user_id)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_user_emails_email_lower_active
    ON user_emails (lower(email))
    WHERE deleted_at IS NULL;

-- =============================================
-- 用户QQ user_qqs
-- =============================================
CREATE TABLE user_qqs
(
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    qq         VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ          DEFAULT NULL
);

CREATE INDEX idx_user_qqs_user_id
    ON user_qqs (user_id);
CREATE UNIQUE INDEX uq_user_qqs_user_id_active
    ON user_qqs (user_id)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_user_qqs_qq_active
    ON user_qqs (qq)
    WHERE deleted_at IS NULL;

-- =============================================
-- TOTP二次验证 user_totp
-- =============================================
CREATE TABLE user_totp
(
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    secret     VARCHAR(256) NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_user_totp PRIMARY KEY (user_id)
);

CREATE TRIGGER trg_user_totp_updated_at
    BEFORE UPDATE
    ON user_totp
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户会话 user_sessions
-- =============================================
CREATE TABLE user_sessions
(
    id                 UUID         NOT NULL PRIMARY KEY DEFAULT uuidv7(),
    user_id            BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    session_token_hash CHAR(128)    NOT NULL, -- sha512
    is_temporary       BOOLEAN      NOT NULL             DEFAULT false,

    created_at         TIMESTAMPTZ  NOT NULL             DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL             DEFAULT now(),
    expires_at         TIMESTAMPTZ  NOT NULL,
    last_used_at       TIMESTAMPTZ                       DEFAULT NULL,
    revoked_at         TIMESTAMPTZ                       DEFAULT NULL,

    last_ip            INET                              DEFAULT NULL,
    last_user_agent    VARCHAR(512) NOT NULL             DEFAULT '',

    CONSTRAINT chk_user_sessions_expires_at CHECK (expires_at > created_at)
);

CREATE INDEX idx_user_sessions_user_id
    ON user_sessions (user_id);
CREATE INDEX idx_user_sessions_user_active
    ON user_sessions (user_id)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX uq_user_sessions_token_hash_active
    ON user_sessions (session_token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_expires_active
    ON user_sessions (expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_last_used_at
    ON user_sessions (last_used_at);
CREATE INDEX idx_user_sessions_revoked_at
    ON user_sessions (revoked_at);

CREATE TRIGGER trg_user_sessions_updated_at
    BEFORE UPDATE
    ON user_sessions
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 注册请求 register_requests
-- =============================================
CREATE TABLE register_requests
(
    id               UUID                    NOT NULL PRIMARY KEY DEFAULT uuidv7(),

    type             user_type               NOT NULL             DEFAULT 'student',
    student_num      VARCHAR(16)                                  DEFAULT NULL,
    real_name        VARCHAR(32)             NOT NULL,
    school           school                  NOT NULL             DEFAULT 'fdfz',

    username         VARCHAR(32)             NOT NULL,
    nickname         VARCHAR(32)                                  DEFAULT NULL,
    password         VARCHAR(256)            NOT NULL, -- argon2id

    created_at       TIMESTAMPTZ             NOT NULL             DEFAULT now(),
    status           register_request_status NOT NULL             DEFAULT 'pending',
    created_user_id  BIGINT REFERENCES users (id) ON DELETE RESTRICT,
    review_comment   TEXT                    NOT NULL             DEFAULT '',
    reviewer_user_id BIGINT REFERENCES users (id) ON DELETE RESTRICT,
    reviewed_at      TIMESTAMPTZ                                  DEFAULT NULL,

    CONSTRAINT chk_register_requests_student_num
        CHECK ((type = 'student' AND student_num IS NOT NULL) OR (type <> 'student' AND student_num IS NULL))
);

CREATE INDEX idx_register_requests_student_num
    ON register_requests (student_num);
CREATE INDEX idx_register_requests_pending
    ON register_requests (status)
    WHERE reviewed_at IS NULL;
CREATE INDEX idx_register_requests_created_user_id
    ON register_requests (created_user_id)
    WHERE created_user_id IS NOT NULL;
CREATE INDEX idx_register_requests_reviewer_user_id
    ON register_requests (reviewer_user_id);
CREATE UNIQUE INDEX uq_register_requests_school_student_num_pending
    ON register_requests (school, student_num)
    WHERE status = 'pending' AND type = 'student';
CREATE UNIQUE INDEX uq_register_requests_username_pending
    ON register_requests (lower(username))
    WHERE status = 'pending';

-- =============================================
-- 应用 apps
-- =============================================
CREATE TABLE apps
(
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace       VARCHAR(32)    NOT NULL,
    owner_user_id   BIGINT         NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    secret_hash     CHAR(128)               DEFAULT NULL, -- sha512

    name            VARCHAR(128)   NOT NULL,
    description     TEXT           NOT NULL DEFAULT '',
    homepage_url    TEXT           NOT NULL DEFAULT '',

    client_type     app_type       NOT NULL DEFAULT 'confidential',
    redirect_uris   VARCHAR(512)[] NOT NULL DEFAULT '{}',
    requested_perms TEXT[]         NOT NULL DEFAULT '{}',

    status          app_status     NOT NULL DEFAULT 'active',

    created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ             DEFAULT NULL
);

CREATE UNIQUE INDEX uq_apps_namespace_lower_active
    ON apps (lower(namespace))
    WHERE deleted_at IS NULL;
CREATE INDEX idx_apps_owner_user_id
    ON apps (owner_user_id);
CREATE INDEX idx_apps_status
    ON apps (status)
    WHERE deleted_at IS NULL;

CREATE TRIGGER trg_apps_updated_at
    BEFORE UPDATE
    ON apps
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 权限定义 permission_defs
-- =============================================
CREATE TABLE permission_defs
(
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id      BIGINT       NOT NULL REFERENCES apps (id) ON DELETE RESTRICT,
    value       VARCHAR(96)  NOT NULL,               -- 路径部分
    description VARCHAR(256) NOT NULL DEFAULT '',
    requestable BOOLEAN      NOT NULL DEFAULT false, -- OAuth 可申请
    created_by  BIGINT                DEFAULT NULL REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_permission_defs_app_value UNIQUE (app_id, value)
);

CREATE INDEX idx_permission_defs_created_by
    ON permission_defs (created_by)
    WHERE created_by IS NOT NULL;

CREATE TRIGGER trg_permission_defs_updated_at
    BEFORE UPDATE
    ON permission_defs
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 权限继承 permission_implies
-- =============================================
CREATE TABLE permission_implies
(
    permission_id         BIGINT       NOT NULL REFERENCES permission_defs (id) ON DELETE CASCADE,
    implied_permission_id BIGINT       NOT NULL REFERENCES permission_defs (id) ON DELETE CASCADE,

    -- 授权记录：granted_by_user_id 为 NULL 表示系统内置；时间窗为空表示永久有效。
    granted_by_user_id    BIGINT                DEFAULT NULL REFERENCES users (id) ON DELETE SET NULL,
    valid_from            TIMESTAMPTZ           DEFAULT NULL,
    valid_until           TIMESTAMPTZ           DEFAULT NULL,
    note                  VARCHAR(256) NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    PRIMARY KEY (permission_id, implied_permission_id),
    CONSTRAINT chk_permission_implies_not_self CHECK (permission_id <> implied_permission_id),
    CONSTRAINT chk_permission_implies_valid_range
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE INDEX idx_permission_implies_implied_permission_id
    ON permission_implies (implied_permission_id);
CREATE INDEX idx_permission_implies_granted_by_user_id
    ON permission_implies (granted_by_user_id)
    WHERE granted_by_user_id IS NOT NULL;

CREATE TRIGGER trg_permission_implies_updated_at
    BEFORE UPDATE
    ON permission_implies
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户组 roles
-- =============================================
CREATE TABLE roles
(
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id     BIGINT       NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    name       VARCHAR(128) NOT NULL,
    note       VARCHAR(256) NOT NULL DEFAULT '',
    is_public  BOOLEAN      NOT NULL DEFAULT false,
    is_system  BOOLEAN      NOT NULL DEFAULT false, -- 系统用户组：由平台创建与分配，不允许删除或重命名
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_roles_app_id_name UNIQUE (app_id, name)
);

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE
    ON roles
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户组包含的权限模式 role_permissions
-- permission 为完整权限模式（如 student_id:users.*），支持 * / ** 通配，运行时展开。
-- =============================================
CREATE TABLE role_permissions
(
    role_id            BIGINT       NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission         VARCHAR(128) NOT NULL,
    granted_by_user_id BIGINT                DEFAULT NULL REFERENCES users (id) ON DELETE SET NULL, -- null 表示系统
    valid_from         TIMESTAMPTZ           DEFAULT NULL,
    valid_until        TIMESTAMPTZ           DEFAULT NULL,
    note               VARCHAR(256) NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),

    PRIMARY KEY (role_id, permission),
    CONSTRAINT chk_role_permissions_valid_range
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE TRIGGER trg_role_permissions_updated_at
    BEFORE UPDATE
    ON role_permissions
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

CREATE INDEX idx_role_permissions_granted_by_user_id
    ON role_permissions (granted_by_user_id)
    WHERE granted_by_user_id IS NOT NULL;

-- =============================================
-- 用户组成员 user_roles
-- =============================================
CREATE TABLE user_roles
(
    user_id     BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     BIGINT      NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_by  BIGINT               DEFAULT NULL REFERENCES users (id) ON DELETE SET NULL, -- null 表示系统
    valid_from  TIMESTAMPTZ          DEFAULT NULL,
    valid_until TIMESTAMPTZ          DEFAULT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT chk_user_roles_valid_range
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE INDEX idx_user_roles_role_id
    ON user_roles (role_id);
CREATE INDEX idx_user_roles_granted_by
    ON user_roles (granted_by)
    WHERE granted_by IS NOT NULL;

-- =============================================
-- 用户直接权限授权 user_permission_grants
-- =============================================
CREATE TABLE user_permission_grants
(
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id            BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission         VARCHAR(128) NOT NULL,
    granted_by_user_id BIGINT                DEFAULT NULL REFERENCES users (id) ON DELETE SET NULL, -- null 表示系统
    granted_by_app_id  BIGINT       NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    valid_from         TIMESTAMPTZ           DEFAULT NULL,
    valid_until        TIMESTAMPTZ           DEFAULT NULL,
    note               VARCHAR(256) NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_user_permission_grants_user_permission UNIQUE (user_id, permission),
    CONSTRAINT chk_user_permission_grants_valid_range
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE INDEX idx_user_permission_grants_permission
    ON user_permission_grants (permission);
CREATE INDEX idx_user_permission_grants_granted_by_app_id
    ON user_permission_grants (granted_by_app_id)
    WHERE granted_by_app_id IS NOT NULL;
CREATE INDEX idx_user_permission_grants_granted_by_user_id
    ON user_permission_grants (granted_by_user_id)
    WHERE granted_by_user_id IS NOT NULL;

CREATE TRIGGER trg_user_permission_grants_updated_at
    BEFORE UPDATE
    ON user_permission_grants
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- OAuth 用户授权 oauth_authorizations
-- =============================================
CREATE TABLE oauth_authorizations
(
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT          NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app_id       BIGINT          NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    permissions  TEXT[]          NOT NULL DEFAULT '{}',
    status       app_auth_status NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ              DEFAULT NULL,

    CONSTRAINT uq_oauth_authorizations_user_id_app_id UNIQUE (user_id, app_id)
);

CREATE INDEX idx_oauth_authorizations_app_id
    ON oauth_authorizations (app_id);

CREATE TRIGGER trg_oauth_authorizations_updated_at
    BEFORE UPDATE
    ON oauth_authorizations
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- OAuth 刷新令牌 oauth_refresh_tokens
-- =============================================
CREATE TABLE oauth_refresh_tokens
(
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    auth_id      BIGINT      NOT NULL REFERENCES oauth_authorizations (id) ON DELETE CASCADE,
    token_hash   CHAR(128)   NOT NULL, -- sha512
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ          DEFAULT NULL,

    CONSTRAINT uq_oauth_refresh_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_oauth_refresh_tokens_auth_id
    ON oauth_refresh_tokens (auth_id);
CREATE INDEX idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens (expires_at);

-- =============================================
-- 内置管理员用户与核心应用
--
-- 内置管理员固定为 id=1；默认密码 Admin123456（Argon2id），首次登录后请立即修改。
-- =============================================
DO
$$
    DECLARE
        admin_user_id BIGINT;
        core_app_id   BIGINT;
    BEGIN
        INSERT INTO users (username, type, real_name, school)
        VALUES ('admin', 'teacher', '管理员', 'fdfz')
        RETURNING id INTO admin_user_id;

        IF admin_user_id <> 1 THEN
            RAISE EXCEPTION '内置管理员必须是第一个用户（id=1），当前 id=%', admin_user_id;
        END IF;

        INSERT INTO user_passwords (user_id, password)
        VALUES (admin_user_id,
                '$argon2id$v=19$m=65536,t=3,p=4$fber5HgkNuz/FmQ+2gafV8K4F3A2ZOR1yoR4zCLeuJA$ROQzMHzBF8iJkgMHbkMD+GHH1E8YORH49FGGAFcVMog');

        INSERT INTO apps (namespace, owner_user_id, name, description, homepage_url,
                          client_type, redirect_uris, requested_perms, status)
        VALUES ('student_id', admin_user_id, '统一身份认证', 'FDFZ 学生身份与统一认证平台', '',
                'confidential', '{}', '{}', 'active')
        RETURNING id INTO core_app_id;

        RAISE NOTICE '已创建内置管理员（id=%）与核心应用（id=%, namespace=student_id）', admin_user_id, core_app_id;
    END
$$;

COMMIT;
