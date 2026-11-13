package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// createAppRequest 是创建 OAuth 应用的请求体：只需命名空间、名称与所有者，其余字段使用默认值。
type createAppRequest struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	OwnerUserID int64  `json:"owner_user_id"`
}

// createAppHandler 管理员创建 OAuth 应用并分配给指定用户。
// 命名空间全站唯一且不可使用系统保留值；客户端类型默认为 confidential，状态默认为 active，
// 不自动生成客户端密钥，所有者可在需要时通过密钥轮换接口自行生成。
func createAppHandler(c *gin.Context) *errs.Error {
	var req createAppRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	// 只校验必填的命名空间、名称与所有者
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

	// 提前给出更友好的命名空间冲突提示；并发创建仍由数据库唯一索引兜底
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
