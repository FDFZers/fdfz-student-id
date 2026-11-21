BEGIN;

-- =============================================
-- 站内通知 notifications
-- 一个用户可有多条通知；content 保存 Markdown 原文，ext 保存业务附加信息（JSON 对象）。
-- 来源二选一：
--   app_id          应用发送（应用通知、平台安全通知等）；
--   sender_user_id  管理员发送，对接收用户只展示「管理员」，不暴露管理员用户 ID。
-- icon 是前端渲染用的 Lucide 图标名，空字符串表示由前端决定。
-- =============================================
CREATE TABLE notifications
(
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app_id         BIGINT                REFERENCES apps (id) ON DELETE RESTRICT,
    sender_user_id BIGINT                REFERENCES users (id) ON DELETE RESTRICT,
    icon           VARCHAR(64)  NOT NULL DEFAULT '',
    title          VARCHAR(256) NOT NULL,
    content        TEXT         NOT NULL, -- Markdown 正文
    ext            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    read_at        TIMESTAMPTZ           DEFAULT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT chk_notifications_source
        CHECK ((app_id IS NULL) <> (sender_user_id IS NULL)),
    CONSTRAINT chk_notifications_icon
        CHECK (icon = '' OR icon ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_notifications_ext
        CHECK (jsonb_typeof(ext) = 'object')
);

-- 列表按用户 + 时间倒序查询
CREATE INDEX idx_notifications_user_created
    ON notifications (user_id, created_at DESC, id DESC);

-- 未读数与「仅看未读」查询
CREATE INDEX idx_notifications_user_unread
    ON notifications (user_id)
    WHERE read_at IS NULL;

-- 按来源应用 / 来源管理员查询
CREATE INDEX idx_notifications_app_id
    ON notifications (app_id)
    WHERE app_id IS NOT NULL;
CREATE INDEX idx_notifications_sender_user_id
    ON notifications (sender_user_id)
    WHERE sender_user_id IS NOT NULL;

COMMIT;
