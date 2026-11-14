package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

type createAppRequest struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	OwnerUserID int64  `json:"owner_user_id"`
}

// createAppHandler 管理员创建 OAuth 应用并分配给指定用户；命名空间全站唯一，不自动生成客户端密钥。
func createAppHandler(c *gin.Context) *errs.Error {
	var req createAppRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	if err := handling.ValidateAppNamespace(req.Namespace); err != nil {
		return err
	}
	if err := handling.ValidateAppName(req.Name); err != nil {
		return err
	}
	if err := handling.ValidateAppOwnerID(req.OwnerUserID); err != nil {
		return err
	}
	if err := handling.EnsureUserExists(c, req.OwnerUserID); err != nil {
		return err
	}

	// 预检只提供友好提示，并发创建仍由数据库唯一索引兜底。
	existing, err := appsvc.GetAppByNamespace(c.Request.Context(), req.Namespace)
	if err != nil {
		return err
	}
	if existing != nil {
		return errs.ConflictError().AppendDetails("命名空间已存在")
	}

	a := &model.OAuthApp{
		Namespace:   req.Namespace,
		OwnerUserID: req.OwnerUserID,
		Name:        req.Name,
		ClientType:  model.AppTypeConfidential,
		Status:      model.AppStatusActive,
	}
	if err := appsvc.CreateApp(c.Request.Context(), a); err != nil {
		return err
	}

	respondApp(c, a)
	return nil
}
