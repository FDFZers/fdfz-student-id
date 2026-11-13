package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// updateAppRequest 是修改应用的请求体；字段为 nil 表示不修改，空数组表示清空列表。
// namespace、owner_user_id 为管理员专属字段，所有者提交会被拒绝。
type updateAppRequest struct {
	Namespace      *string        `json:"namespace"`
	OwnerUserID    *int64         `json:"owner_user_id"`
	Name           *string        `json:"name"`
	Description    *string        `json:"description"`
	HomepageURL    *string        `json:"homepage_url"`
	ClientType     *model.AppType `json:"client_type"`
	RedirectURIs   *[]string      `json:"redirect_uris"`
	RequestedPerms *[]string      `json:"requested_perms"`
}

// empty 判断请求是否未提供任何可修改字段。
func (r *updateAppRequest) empty() bool {
	return r.Namespace == nil &&
		r.OwnerUserID == nil &&
		r.Name == nil &&
		r.Description == nil &&
		r.HomepageURL == nil &&
		r.ClientType == nil &&
		r.RedirectURIs == nil &&
		r.RequestedPerms == nil
}

// updateAppHandler 修改应用：管理员可修改全部可管理字段，应用所有者只能修改资料类字段。
// 命名空间变化会级联改写授权中的权限串；客户端类型在 public 与 confidential 之间转换时自动清理/生成密钥。
// 写库使用 updated_at 乐观锁，应用并发修改时返回 409。
func updateAppHandler(c *gin.Context) *errs.Error {
	var req updateAppRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if req.empty() {
		return errs.BadRequestError().AppendDetails("没有需要更新的字段")
	}

	a, err := managedApp(c, true)
	if err != nil {
		return err
	}
	claims := handling.MustGetClaims(c)
	expectedUpdatedAt := a.UpdatedAt
	oldNamespace := a.Namespace

	// 命名空间与所有者仅管理员可改；所有者提交原值（未实际修改）时放行，
	// 以兼容客户端携带完整对象的 PATCH 请求。状态变化走独立的停用/启用接口。
	if !handling.IsGlobalAppAdmin(claims) {
		if req.Namespace != nil && *req.Namespace != a.Namespace {
			return errs.PermissionDeniedError().AppendDetails("仅管理员可修改命名空间与所有者").Seal()
		}
		if req.OwnerUserID != nil && *req.OwnerUserID != a.OwnerUserID {
			return errs.PermissionDeniedError().AppendDetails("仅管理员可修改命名空间与所有者").Seal()
		}
	}

	// 逐个字段校验后合并到应用记录
	if req.Namespace != nil && *req.Namespace != a.Namespace {
		if a.Namespace == appsvc.CoreNamespace {
			return errs.IllegalStateError().AppendDetails("核心应用的命名空间不允许修改").Seal()
		}
		if err := handling.ValidateAppNamespace(*req.Namespace); err != nil {
			return err
		}
		existing, err := appsvc.GetAppByNamespace(c.Request.Context(), *req.Namespace)
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != a.ID {
			return errs.ConflictError().AppendDetails("命名空间已存在")
		}
		a.Namespace = *req.Namespace
	}
	if req.OwnerUserID != nil && *req.OwnerUserID != a.OwnerUserID {
		if err := handling.ValidateAppOwnerID(*req.OwnerUserID); err != nil {
			return err
		}
		if err := handling.EnsureUserExists(c, *req.OwnerUserID); err != nil {
			return err
		}
		a.OwnerUserID = *req.OwnerUserID
	}
	if req.Name != nil {
		if err := handling.ValidateAppName(*req.Name); err != nil {
			return err
		}
		a.Name = *req.Name
	}
	if req.Description != nil {
		if err := handling.ValidateAppDescription(*req.Description); err != nil {
			return err
		}
		a.Description = *req.Description
	}
	if req.HomepageURL != nil {
		if err := handling.ValidateAppHomepageURL(*req.HomepageURL); err != nil {
			return err
		}
		a.HomepageURL = *req.HomepageURL
	}
	if req.ClientType != nil {
		if err := handling.ValidateAppClientType(*req.ClientType); err != nil {
			return err
		}
		a.ClientType = *req.ClientType
	}
	if req.RedirectURIs != nil {
		redirectURIs := dedupeStrings(*req.RedirectURIs)
		if err := handling.ValidateAppRedirectURIs(redirectURIs); err != nil {
			return err
		}
		a.RedirectURIs = redirectURIs
	}
	if req.RequestedPerms != nil {
		requestedPerms := dedupeStrings(*req.RequestedPerms)
		if err := handling.ValidateAppRequestedPermissions(requestedPerms); err != nil {
			return err
		}
		a.RequestedPerms = requestedPerms
	}

	// public 客户端不保留密钥；confidential 是否配置密钥由所有者通过密钥轮换自行决定。
	if !a.ClientType.IsConfidential() {
		a.SecretHash = null.String{}
	}

	if err := appsvc.UpdateApp(c.Request.Context(), a, oldNamespace, expectedUpdatedAt); err != nil {
		return err
	}

	respondApp(c, a)
	return nil
}
