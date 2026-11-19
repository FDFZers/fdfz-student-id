package oauth

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/slicex"

	"github.com/google/uuid"
	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Permissions  []string `json:"permissions"`
}

// ---------------------------------------------------------------------------
// 签发
// ---------------------------------------------------------------------------

// issueAccessToken 签发 RS512 JWT 访问令牌，权限 ID 排序去重后写入 claims。
// OAuth 令牌同样只携带权限 ID，客户端可通过 /api/internal/auth/claims 换取具体权限串。
func issueAccessToken(userID, appID, authID int64, permissions []string) (string, int64, error) {
	token, err := crypto.GenerateJWT(uuid.New(), &model.TokenClaims{
		UserID:      userID,
		TokenType:   model.TokenTypeOAuth,
		AppID:       null.StringFrom(strconv.FormatInt(appID, 10)),
		AuthID:      null.IntFrom(authID),
		Permissions: permsvc.ToIDs(slicex.DedupeStrings(permissions)),
	}, cfg.C.OAuthAccessTokenTTL)
	if err != nil {
		return "", 0, err
	}
	return token, int64(cfg.C.OAuthAccessTokenTTL / time.Second), nil
}

func newRefreshToken() (string, string, error) {
	raw, err := crypto.GenerateCode(64, crypto.TokenCharset)
	if err != nil {
		return "", "", err
	}
	return raw, crypto.HashSHA512(raw), nil
}

// ---------------------------------------------------------------------------
// 交换
// ---------------------------------------------------------------------------

// ExchangeAuthorizationCode 用授权码换取访问令牌与刷新令牌，授权码取出即删除。
func ExchangeAuthorizationCode(
	ctx context.Context,
	client *model.OAuthApp,
	code string,
	codeVerifier string,
	redirectURI string,
) (*TokenResponse, *errs.Error) {
	if code == "" {
		return nil, errs.BadRequestError().AppendDetails("缺少授权码")
	}

	stored, err := takeAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, errs.BadRequestError().AppendDetails("授权码无效或已被使用")
	}
	if stored.AppID != client.ID {
		return nil, errs.BadRequestError().AppendDetails("授权码无效或已被使用")
	}
	if !time.Now().Before(stored.ExpiresAt) {
		return nil, errs.BadRequestError().AppendDetails("授权码已过期")
	}
	// RFC 6749：授权请求带过 redirect_uri 时，令牌请求必须原样传回并精确匹配。
	if stored.RedirectURIProvided && redirectURI != stored.RedirectURI {
		return nil, errs.BadRequestError().AppendDetails("redirect_uri 与授权请求不一致")
	}
	// RFC 7636：公开客户端没有密钥，必须用 PKCE 防止授权码被截获。
	if !client.ClientType.IsConfidential() && stored.CodeChallenge == "" {
		return nil, errs.BadRequestError().AppendDetails("公开客户端必须使用 PKCE")
	}
	if !crypto.VerifyCodeChallenge(stored.CodeChallenge, codeVerifier) {
		return nil, errs.BadRequestError().AppendDetails("code_verifier 校验失败")
	}

	state, err := loadAuthorizationForToken(ctx, db.R, stored.AuthID, stored.AppID, stored.UserID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errs.BadRequestError().AppendDetails("授权记录不存在")
	}
	if state.AuthStatus != model.AppAuthStatusActive ||
		state.AppStatus != model.AppStatusActive || state.UserDeletedAt.Valid {
		return nil, errs.BadRequestError().AppendDetails("授权已失效")
	}

	permissions, err := effectiveGrantPermissions(ctx, stored.UserID, state.Permissions)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenHash, e := newRefreshToken()
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to generate oauth refresh token").AppendDetails("令牌生成失败")
	}

	// 先生成访问令牌再写库，避免签名失败后留下无法交付的刷新令牌。
	accessToken, expiresIn, e := issueAccessToken(stored.UserID, stored.AppID, stored.AuthID, permissions)
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to issue oauth access token").AppendDetails("令牌生成失败")
	}

	if err := touchAuthorization(ctx, db.R, stored.AuthID); err != nil {
		return nil, err
	}
	if err := insertRefreshToken(ctx, db.R, stored.AuthID, refreshTokenHash, time.Now().Add(cfg.C.OAuthRefreshTokenTTL)); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Permissions:  permissions,
	}, nil
}

// ExchangeRefreshToken 用刷新令牌换发访问令牌并轮换刷新令牌。
func ExchangeRefreshToken(
	ctx context.Context,
	dh db.Handle,
	client *model.OAuthApp,
	refreshToken string,
) (*TokenResponse, *errs.Error) {
	if refreshToken == "" {
		return nil, errs.BadRequestError().AppendDetails("缺少刷新令牌")
	}

	tx, e := dh.Begin(ctx)
	if e != nil {
		return nil, errs.CreatePGError(e, "OAuth 刷新令牌", "Failed to begin transaction")
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			slog.Error("Failed to rollback transaction", "err", err)
		}
	}(tx, ctx)

	record, err := loadRefreshTokenForUpdate(ctx, tx, crypto.HashSHA512(refreshToken))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, errs.BadRequestError().AppendDetails("刷新令牌无效或已被使用")
	}

	invalidReason := ""
	switch {
	case record.AppID != client.ID:
		invalidReason = "刷新令牌无效或已被使用"
	case !time.Now().Before(record.ExpiresAt):
		invalidReason = "刷新令牌已过期"
	case record.AuthStatus != model.AppAuthStatusActive ||
		record.AppStatus != model.AppStatusActive || record.UserDeletedAt.Valid:
		invalidReason = "授权已失效"
	}
	if invalidReason != "" {
		if _, err := deleteRefreshTokenByID(ctx, tx, record.ID); err != nil {
			return nil, err
		}
		if e := tx.Commit(ctx); e != nil {
			return nil, errs.CreatePGError(e, "OAuth 刷新令牌", "Failed to commit oauth refresh token revocation")
		}
		return nil, errs.BadRequestError().AppendDetails(invalidReason)
	}

	permissions, err := effectiveGrantPermissions(ctx, record.UserID, record.Permissions)
	if err != nil {
		return nil, err
	}

	newToken, newTokenHash, e := newRefreshToken()
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to generate oauth refresh token").AppendDetails("令牌生成失败")
	}

	accessToken, expiresIn, e := issueAccessToken(record.UserID, record.AppID, record.AuthID, permissions)
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to issue oauth access token").AppendDetails("令牌生成失败")
	}

	deleted, err := deleteRefreshTokenByID(ctx, tx, record.ID)
	if err != nil {
		return nil, err
	}
	if !deleted {
		// 行锁下删不到说明令牌已被并发消费，必须回滚，不能签发第二套令牌。
		return nil, errs.BadRequestError().AppendDetails("刷新令牌无效或已被使用")
	}
	if err := touchAuthorization(ctx, tx, record.AuthID); err != nil {
		return nil, err
	}
	if err := insertRefreshToken(ctx, tx, record.AuthID, newTokenHash, time.Now().Add(cfg.C.OAuthRefreshTokenTTL)); err != nil {
		return nil, err
	}

	if e := tx.Commit(ctx); e != nil {
		return nil, errs.CreatePGError(e, "OAuth 刷新令牌", "Failed to commit oauth refresh")
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: newToken,
		Permissions:  permissions,
	}, nil
}

// ---------------------------------------------------------------------------
// 吊销
// ---------------------------------------------------------------------------

// RevokeRefreshToken 吊销客户端自己的刷新令牌；令牌不存在或不属于该客户端时也返回成功，避免泄露令牌是否存在。
func RevokeRefreshToken(
	ctx context.Context,
	client *model.OAuthApp,
	refreshToken string,
) *errs.Error {
	if refreshToken == "" {
		return errs.BadRequestError().AppendDetails("缺少刷新令牌")
	}

	refreshTokenID, appID, err := findRefreshTokenOwner(ctx, db.R, crypto.HashSHA512(refreshToken))
	if err != nil {
		return err
	}
	if refreshTokenID == 0 || appID != client.ID {
		return nil
	}
	_, err = deleteRefreshTokenByID(ctx, db.R, refreshTokenID)
	return err
}
