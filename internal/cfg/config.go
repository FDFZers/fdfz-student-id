package cfg

import (
	"encoding/json"
	"fdfz-student-id/internal/model"
	"fmt"
	"os"
	"strings"
	"time"
)

var C *Config

type Config struct {
	PostgresURL      string
	RedisURL         string
	FilestoreSite    string
	APIKey           string
	AltchaHMACSecret string
	JWTSecret        string
	AccessTokenTTL   time.Duration
	SessionTokenTTL  time.Duration
	SMTP             SMTPConfig
	SchoolIPs        map[string]model.School
	TrustedProxies   []string
	SharedDir        string
}

type SMTPConfig struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string
}

func LoadConfig() error {
	cfg := &Config{}
	var err error

	if cfg.PostgresURL, err = requireEnv("POSTGRESQL_URL"); err != nil {
		return err
	}
	if cfg.RedisURL, err = requireEnv("REDIS_URL"); err != nil {
		return err
	}

	cfg.FilestoreSite = env("FILESTORE_SITE", "https://static.fdfz.top/")
	cfg.AccessTokenTTL = envDur("ACCESS_TOKEN_TTL", 15*time.Minute)
	cfg.SessionTokenTTL = envDur("SESSION_TOKEN_TTL", 30*24*time.Hour)
	cfg.SMTP.Host = env("SMTP_HOST", "mail.fdfz.top")
	cfg.SMTP.Port = env("SMTP_PORT", "587")
	cfg.SMTP.From = env("SMTP_FROM", "FDFZ Bot <noreply@fdfz.top>")
	cfg.SMTP.Username = env("SMTP_USERNAME", "<noreply@fdfz.top>")
	cfg.SharedDir = env("SHARED_DIR", "./shared")

	if cfg.SMTP.Password, err = requireEnv("SMTP_PASSWORD"); err != nil {
		return err
	}

	raw, err := requireEnv("SCHOOL_IPS")
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), &cfg.SchoolIPs); err != nil {
		return fmt.Errorf("load env: invalid json SCHOOL_IPS: %w", err)
	}

	if cfg.APIKey, err = requireEnv("API_KEY"); err != nil {
		return err
	} else if len(cfg.APIKey) == 0 {
		return fmt.Errorf("API key not set")
	}

	if cfg.AltchaHMACSecret, err = requireEnv("ALTCHA_HMAC_SECRET"); err != nil {
		return err
	} else if len(cfg.AltchaHMACSecret) == 0 {
		return fmt.Errorf("Altcha HMAC secret not set")
	}

	if cfg.JWTSecret, err = requireEnv("JWT_SECRET"); err != nil {
		return err
	} else if len(cfg.JWTSecret) == 0 {
		return fmt.Errorf("JWT secret not set")
	}

	for p := range strings.SplitSeq(env("TRUSTED_PROXIES", ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			cfg.TrustedProxies = append(cfg.TrustedProxies, p)
		}
	}

	C = cfg
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func requireEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("load env: %s is required", key)
	}
	return v, nil
}
