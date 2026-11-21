package app

import (
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"
	"fdfz-student-id/internal/util/slicex"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// updateAppRequest 是修改应用的请求体；字段为 nil 表示不修改，空数组表示清空列表。
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
// 命名空间变化会级联改写授权中的权限串；写库使用 updated_at 乐观锁，并发修改返回 409。
func updateAppHandler(c *gin.Context) *errs.Error {
	var req updateAppRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
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

	// 所有者原样提交命名空间与所有者字段时放行，兼容携带完整对象的 PATCH 请求。
	if !handling.IsGlobalAppAdmin(claims) {
		if req.Namespace != nil && *req.Namespace != a.Namespace {
			return errs.PermissionDeniedError().AppendDetails("仅管理员可修改命名空间与所有者").Seal()
		}
		if req.OwnerUserID != nil && *req.OwnerUserID != a.OwnerUserID {
			return errs.PermissionDeniedError().AppendDetails("仅管理员可修改命名空间与所有者").Seal()
		}
	}

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
		redirectURIs := slicex.DedupeStrings(*req.RedirectURIs)
		if err := handling.ValidateAppRedirectURIs(redirectURIs); err != nil {
			return err
		}
		a.RedirectURIs = redirectURIs
	}
	if req.RequestedPerms != nil {
		requestedPerms := slicex.DedupeStrings(*req.RequestedPerms)
		if err := handling.ValidateAppRequestedPermissions(requestedPerms); err != nil {
			return err
		}
		a.RequestedPerms = requestedPerms
	}

	if !a.ClientType.SupportsSecret() {
		a.SecretHash = null.String{}
	}

	if err := appsvc.UpdateApp(c.Request.Context(), db.R, a, oldNamespace, expectedUpdatedAt); err != nil {
		return err
	}

	respondApp(c, a)
	return nil
}
