package cfg

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"strings"
	"time"
)

// C 是全局配置单例，由 LoadConfig 初始化；其它包通过 cfg.C 读取。
var C *Config

// Config 汇总运行所需的全部配置。字段后的注释标注对应环境变量与默认值。
type Config struct {
	PostgresURL string // PostgreSQL 连接串，必填：POSTGRESQL_URL
	RedisURL    string // Redis 连接串，必填：REDIS_URL

	AltchaHMACSecret string        // Altcha 人机验证的 HMAC 密钥，必填：ALTCHA_HMAC_SECRET
	AltchaTimeout    time.Duration // Altcha challenge 有效期，默认 30s：ALTCHA_TIMEOUT
	JWTKeyID         string        // JWT 签名密钥（类似 kid 的字符串），必填：JWT_KID

	AccessTokenTTL      time.Duration // 访问令牌有效期，默认 10m：ACCESS_TOKEN_TTL
	StepupTokenTTL      time.Duration // 提权令牌有效期，默认 5m：STEPUP_TOKEN_TTL，必须为正
	TempSessionTokenTTL time.Duration // 临时会话刷新令牌有效期，默认 24h：TEMP_SESSION_TOKEN_TTL
	PermSessionTokenTTL time.Duration // 正式会话刷新令牌有效期，默认 30d：PERM_SESSION_TOKEN_TTL
	CodeSendInterval    time.Duration // 邮箱/QQ 验证码最小发送间隔，默认 1m：CODE_SEND_INTERVAL

	OAuthAccessTokenTTL    time.Duration // 默认 30m：OAUTH_ACCESS_TOKEN_TTL
	OAuthRefreshTokenTTL   time.Duration // 默认 30d：OAUTH_REFRESH_TOKEN_TTL
	OAuthCodeTTL           time.Duration // 默认 60s：OAUTH_CODE_TTL
	OAuthDeviceCodeTTL     time.Duration // 默认 10m：OAUTH_DEVICE_CODE_TTL
	OAuthConsentRequestTTL time.Duration // 默认 10m：OAUTH_CONSENT_REQUEST_TTL

	FilestorePublicEndpoint   string // 文件存储对外访问地址（拼接文件 URL）：FILESTORE_PUBLIC_ENDPOINT
	FilestoreInternalEndpoint string // 文件存储内部调用地址（上传/删除）：FILESTORE_INTERNAL_ENDPOINT
	FilestoreHMACSecret       string // 文件存储接口 HMAC 签名密钥，必填：FILESTORE_HMAC_SECRET
	NapCatEndpoint            string // NapCat（OneBot 11 HTTP）地址：NAPCAT_ENDPOINT
	NapCatToken               string // NapCat 访问令牌，必填：NAPCAT_TOKEN
	AuthFrontendURL           string // 认证前端地址，用于跳转：AUTH_FRONTEND_URL
	SMTP                      SMTPConfig

	SchoolIPs      SchoolIPMatcher // 校园网 IP/CIDR 网段 -> 前端展示文本（JSON），必填：SCHOOL_IPS
	TrustedProxies []string        // 可信反向代理列表（逗号分隔）：TRUSTED_PROXIES
	SharedDir      string          // 本地文件共享目录，默认 ./shared：SHARED_DIR
	BypassCaptcha  bool            // 仅非生产环境生效，跳过 Altcha 校验：BYPASS_CAPTCHA=true
}

// SMTPConfig 是发信服务配置，字段分别来自 SMTP_* 环境变量。
type SMTPConfig struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string // 必填：SMTP_PASSWORD
}

// LoadConfig 从环境变量加载配置并写入全局 cfg.C。
// 必填项缺失时返回 error；可选项使用默认值。
func LoadConfig() error {
	cfg := &Config{}
	var err error

	if cfg.PostgresURL, err = requireEnv("POSTGRESQL_URL"); err != nil {
		return err
	}
	if cfg.RedisURL, err = requireEnv("REDIS_URL"); err != nil {
		return err
	}

	cfg.FilestorePublicEndpoint = env("FILESTORE_PUBLIC_ENDPOINT", "https://filestore.fdfz.top/")
	cfg.FilestoreInternalEndpoint = env("FILESTORE_INTERNAL_ENDPOINT", "https://filestore.fdfz.top/")
	cfg.NapCatEndpoint = env("NAPCAT_ENDPOINT", "http://fdfz.top:7010/")
	cfg.AltchaTimeout = envDur("ALTCHA_TIMEOUT", 30*time.Second)
	cfg.AccessTokenTTL = envDur("ACCESS_TOKEN_TTL", 10*time.Minute)
	cfg.PermSessionTokenTTL = envDur("PERM_SESSION_TOKEN_TTL", 30*24*time.Hour)
	cfg.TempSessionTokenTTL = envDur("TEMP_SESSION_TOKEN_TTL", 24*time.Hour)
	cfg.CodeSendInterval = envDur("CODE_SEND_INTERVAL", 1*time.Minute)
	cfg.SMTP.Host = env("SMTP_HOST", "mail.fdfz.top")
	cfg.SMTP.Port = env("SMTP_PORT", "587")
	cfg.SMTP.From = env("SMTP_FROM", "FDFZ Bot <noreply@fdfz.top>")
	cfg.SMTP.Username = env("SMTP_USERNAME", "noreply@fdfz.top")
	cfg.BypassCaptcha = !IsProd && env("BYPASS_CAPTCHA", "false") == "true"
	cfg.SharedDir = env("SHARED_DIR", "./shared")
	cfg.AuthFrontendURL = env("AUTH_FRONTEND_URL", "https://auth.fdfz.top")
	cfg.OAuthAccessTokenTTL = envDur("OAUTH_ACCESS_TOKEN_TTL", 30*time.Minute)
	cfg.OAuthRefreshTokenTTL = envDur("OAUTH_REFRESH_TOKEN_TTL", 30*24*time.Hour)
	cfg.OAuthCodeTTL = envDur("OAUTH_CODE_TTL", 60*time.Second)
	cfg.OAuthDeviceCodeTTL = envDur("OAUTH_DEVICE_CODE_TTL", 10*time.Minute)
	cfg.OAuthConsentRequestTTL = envDur("OAUTH_CONSENT_REQUEST_TTL", 10*time.Minute)

	if cfg.StepupTokenTTL = envDur("STEPUP_TOKEN_TTL", 5*time.Minute); cfg.StepupTokenTTL <= 0 {
		return fmt.Errorf("stepup token ttl must be positive")
	}

	for name, d := range map[string]time.Duration{
		"ALTCHA_TIMEOUT":            cfg.AltchaTimeout,
		"ACCESS_TOKEN_TTL":          cfg.AccessTokenTTL,
		"TEMP_SESSION_TOKEN_TTL":    cfg.TempSessionTokenTTL,
		"PERM_SESSION_TOKEN_TTL":    cfg.PermSessionTokenTTL,
		"CODE_SEND_INTERVAL":        cfg.CodeSendInterval,
		"OAUTH_ACCESS_TOKEN_TTL":    cfg.OAuthAccessTokenTTL,
		"OAUTH_REFRESH_TOKEN_TTL":   cfg.OAuthRefreshTokenTTL,
		"OAUTH_CODE_TTL":            cfg.OAuthCodeTTL,
		"OAUTH_DEVICE_CODE_TTL":     cfg.OAuthDeviceCodeTTL,
		"OAUTH_CONSENT_REQUEST_TTL": cfg.OAuthConsentRequestTTL,
	} {
		if d <= 0 {
			return fmt.Errorf("load env: %s must be positive", name)
		}
	}

	// 必填的敏感配置：密钥缺失时直接启动失败，避免以不安全默认值运行。
	if cfg.SMTP.Password, err = requireEnv("SMTP_PASSWORD"); err != nil {
		return err
	}

	if cfg.NapCatToken, err = requireEnv("NAPCAT_TOKEN"); err != nil {
		return err
	}

	if cfg.FilestoreHMACSecret, err = requireEnv("FILESTORE_HMAC_SECRET"); err != nil {
		return err
	} else if len(cfg.FilestoreHMACSecret) == 0 {
		return fmt.Errorf("filestore HMAC secret not set")
	}

	if cfg.AltchaHMACSecret, err = requireEnv("ALTCHA_HMAC_SECRET"); err != nil {
		return err
	} else if len(cfg.AltchaHMACSecret) == 0 {
		return fmt.Errorf("Altcha HMAC secret not set")
	}

	if cfg.JWTKeyID, err = requireEnv("JWT_KID"); err != nil {
		return err
	} else if len(cfg.JWTKeyID) == 0 {
		return fmt.Errorf("JWT kid not set")
	}

	// SCHOOL_IPS 是 JSON 对象，键为精确 IP 或 CIDR 网段，值为前端直接展示的文本：
	// { "1.2.3.4": "复旦大学附属中学", "10.0.0.0/8": "复旦附中徐汇分校" }，
	// 用于判断请求是否来自校园网并给出展示名称。
	raw, err := requireEnv("SCHOOL_IPS")
	if err != nil {
		return err
	}
	var schoolIPRules map[string]string
	if err := json.Unmarshal([]byte(raw), &schoolIPRules); err != nil {
		return fmt.Errorf("load env: invalid json SCHOOL_IPS: %w", err)
	}
	schoolIPs, err := parseSchoolIPMatcher(schoolIPRules)
	if err != nil {
		return fmt.Errorf("load env: invalid SCHOOL_IPS: %w", err)
	}
	cfg.SchoolIPs = schoolIPs

	for p := range strings.SplitSeq(env("TRUSTED_PROXIES", ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			cfg.TrustedProxies = append(cfg.TrustedProxies, p)
		}
	}

	C = cfg
	return nil
}

// env 读取环境变量，未设置或为空字符串时返回默认值 default。
// 注意：因此无法通过环境变量显式把某项配置设为空字符串。
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envDur 按 time.ParseDuration 解析时长环境变量，解析失败时返回默认值 default。
func envDur(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

// requireEnv 读取必填环境变量；变量不存在时返回 error。
// 注意：只检查存在性，允许显式设置为空字符串（与 env 的语义不同）。
func requireEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("load env: %s is required", key)
	}
	return v, nil
}
