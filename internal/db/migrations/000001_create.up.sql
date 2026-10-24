BEGIN;

-- 枚举类型定义
-- =============================================
CREATE TYPE user_type AS ENUM ('student', 'teacher');
CREATE TYPE school AS ENUM ('fdfz', 'ffxh', 'ffqp', 'ffpd', 'ffja');
CREATE TYPE oauth_client_type AS ENUM ('confidential', 'public');
CREATE TYPE register_request_status AS ENUM ('pending', 'approved', 'rejected');

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
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username     VARCHAR(32)  NOT NULL,

    type         user_type    NOT NULL DEFAULT 'student',
    student_num  VARCHAR(8)           DEFAULT NULL,
    real_name    VARCHAR(32)  NOT NULL,
    school       school       NOT NULL DEFAULT 'fdfz',

    nickname     VARCHAR(32)           DEFAULT NULL,
    signature    VARCHAR(128) NOT NULL DEFAULT '',
    bio          TEXT         NOT NULL DEFAULT '',

    visibilities JSONB        NOT NULL DEFAULT '{"real_name":"private"}',

    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ           DEFAULT NULL,

    CHECK ((type = 'student' AND student_num IS NOT NULL) OR (type != 'student' AND student_num IS NULL))
);

CREATE UNIQUE INDEX idx_users_username_lower_active
    ON users (lower(username))
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_student_num_active
    ON users (student_num)
    WHERE type = 'student' AND deleted_at IS NULL;
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

CREATE UNIQUE INDEX idx_user_bans_user_id_active
    ON user_bans (user_id)
    WHERE enabled = true;
CREATE INDEX idx_user_bans_enabled_end_time
    ON user_bans (enabled, end_time);

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
CREATE UNIQUE INDEX idx_user_emails_user_id_active
    ON user_emails (user_id)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_user_emails_lower_active
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
CREATE UNIQUE INDEX idx_user_qqs_user_id_active
    ON user_qqs (user_id)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_user_qqs_qq_active
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
    uuid               UUID         NOT NULL PRIMARY KEY DEFAULT uuidv7(),
    user_id            BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    session_token_hash VARCHAR(128) NOT NULL, -- argon2id
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
CREATE UNIQUE INDEX uq_user_sessions_session_token_active
    ON user_sessions (session_token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_expires_active
    ON user_sessions (expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_last_used
    ON user_sessions (last_used_at);
CREATE INDEX idx_user_sessions_revoked_at
    ON user_sessions (revoked_at);

CREATE TRIGGER trg_user_sessions_updated_at
    BEFORE UPDATE
    ON user_sessions
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 注册申请 register_requests
-- =============================================
CREATE TABLE register_requests
(
    id               UUID                    NOT NULL PRIMARY KEY DEFAULT uuidv7(),

    type             user_type               NOT NULL DEFAULT 'student',
    student_num      VARCHAR(8)                      DEFAULT NULL,
    real_name        VARCHAR(32)             NOT NULL,
    school           school                  NOT NULL DEFAULT 'fdfz',

    username         VARCHAR(32)             NOT NULL,
    nickname         VARCHAR(32)                      DEFAULT NULL,
    password         VARCHAR(256)            NOT NULL, -- argon2id

    created_at       TIMESTAMPTZ             NOT NULL DEFAULT now(),
    status           register_request_status NOT NULL DEFAULT 'pending',
    created_user_id  BIGINT REFERENCES users (id) ON DELETE RESTRICT,
    review_comment   TEXT                    NOT NULL DEFAULT '',
    reviewer_user_id BIGINT REFERENCES users (id) ON DELETE RESTRICT,
    reviewed_at      TIMESTAMPTZ                      DEFAULT NULL,

    CHECK ((type = 'student' AND student_num IS NOT NULL) OR (type != 'student' AND student_num IS NULL))
);

CREATE INDEX idx_register_requests_student_num
    ON register_requests (student_num);
CREATE INDEX idx_register_requests_pending
    ON register_requests (status)
    WHERE reviewed_at IS NULL;
CREATE INDEX idx_register_requests_created_user
    ON register_requests (created_user_id)
    WHERE created_user_id IS NOT NULL;
CREATE INDEX idx_register_requests_reviewer
    ON register_requests (reviewer_user_id);
CREATE UNIQUE INDEX idx_register_requests_student_num_pending
    ON register_requests (student_num)
    WHERE status = 'pending' AND type = 'student';

-- =============================================
-- OAuth应用 oauth_apps
-- =============================================
CREATE TABLE oauth_apps
(
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace             VARCHAR(32)       NOT NULL,
    owner_user_id         BIGINT            NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    secret_hash           VARCHAR(256)      NOT NULL, -- argon2id

    name                  VARCHAR(128)      NOT NULL,
    description           TEXT              NOT NULL DEFAULT '',

    client_type           oauth_client_type NOT NULL DEFAULT 'confidential',
    redirect_uris         VARCHAR(512)[]    NOT NULL DEFAULT '{}',
    requested_permissions JSONB             NOT NULL DEFAULT '[]'::jsonb,

    created_at            TIMESTAMPTZ       NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ       NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ                DEFAULT NULL,

    CONSTRAINT chk_oauth_apps_requested_permissions_array
        CHECK (jsonb_typeof(requested_permissions) = 'array')
);

COMMENT ON COLUMN oauth_apps.requested_permissions IS '申请的权限 {perm: string, reason: string, optional: boolean}[]';

CREATE INDEX idx_oauth_apps_owner
    ON oauth_apps (owner_user_id);
CREATE UNIQUE INDEX idx_oauth_apps_namespace_active
    ON oauth_apps (namespace)
    WHERE deleted_at IS NULL;

CREATE TRIGGER trg_oauth_apps_updated_at
    BEFORE UPDATE
    ON oauth_apps
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 权限定义 permissions
-- =============================================
CREATE TABLE permissions
(
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id      BIGINT       NOT NULL REFERENCES oauth_apps (id) ON DELETE RESTRICT,
    value       VARCHAR(128) NOT NULL,
    description VARCHAR(256) NOT NULL DEFAULT '',
    parents     BIGINT[]     NOT NULL DEFAULT '{}', -- 父权限，递归包含这些权限
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_permissions_app_value UNIQUE (app_id, value)
);

CREATE INDEX idx_permissions_app_id
    ON permissions (app_id);

CREATE TRIGGER trg_permissions_updated_at
    BEFORE UPDATE
    ON permissions
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户权限 user_permissions
-- =============================================
CREATE TABLE user_permissions
(
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    permission  VARCHAR(128) NOT NULL,
    enabled     BOOLEAN      NOT NULL DEFAULT true,
    valid_from  TIMESTAMPTZ           DEFAULT NULL,
    valid_until TIMESTAMPTZ           DEFAULT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    note        VARCHAR(256) NOT NULL DEFAULT '',
    CONSTRAINT uq_user_permissions_user_perm UNIQUE (user_id, permission)
);

CREATE INDEX idx_user_perm_valid
    ON user_permissions (user_id, enabled, valid_from, valid_until);

CREATE TRIGGER trg_user_permissions_updated_at
    BEFORE UPDATE
    ON user_permissions
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

-- =============================================
-- 用户授权应用 user_oauth_apps
-- =============================================
CREATE TABLE user_oauth_apps
(
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT         NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    app_id      BIGINT         NOT NULL REFERENCES oauth_apps (id) ON DELETE RESTRICT,
    permissions VARCHAR(128)[] NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ    NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ             DEFAULT NULL
);

CREATE UNIQUE INDEX uq_user_oauth_apps_user_app_active
    ON user_oauth_apps (user_id, app_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_user_oauth_apps_app_revoked
    ON user_oauth_apps (app_id)
    WHERE revoked_at IS NULL;

CREATE TRIGGER trg_user_oauth_apps_updated_at
    BEFORE UPDATE
    ON user_oauth_apps
    FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();

COMMIT;
