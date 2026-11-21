package handling

import (
	"context"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	usersvc "fdfz-student-id/internal/service/user"
	userpermsvc "fdfz-student-id/internal/service/userperm"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// 本文件集中存放各领域对象的 JSON 渲染函数。

// ---------------------------------------------------------------------------
// 应用
// ---------------------------------------------------------------------------

// AppInfo 是应用对外的统一表示。
type AppInfo struct {
	ID             int64           `json:"id"`
	Namespace      string          `json:"namespace"`
	OwnerUserID    int64           `json:"owner_user_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	HomepageURL    string          `json:"homepage_url"`
	ClientType     model.AppType   `json:"client_type"`
	RedirectURIs   []string        `json:"redirect_uris"`
	RequestedPerms []string        `json:"requested_perms"`
	Status         model.AppStatus `json:"status"`
	HasSecret      bool            `json:"has_secret"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func AppJSON(app *model.OAuthApp) *AppInfo {
	if app == nil {
		return nil
	}

	redirectURIs := app.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	requestedPerms := app.RequestedPerms
	if requestedPerms == nil {
		requestedPerms = []string{}
	}

	return &AppInfo{
		ID:             app.ID,
		Namespace:      app.Namespace,
		OwnerUserID:    app.OwnerUserID,
		Name:           app.Name,
		Description:    app.Description,
		HomepageURL:    app.HomepageURL,
		ClientType:     app.ClientType,
		RedirectURIs:   redirectURIs,
		RequestedPerms: requestedPerms,
		Status:         app.Status,
		HasSecret:      app.ClientType.IsConfidential() && app.SecretHash.Valid,
		CreatedAt:      app.CreatedAt,
		UpdatedAt:      app.UpdatedAt,
	}
}

func AppsJSON(apps []*model.OAuthApp) []*AppInfo {
	result := make([]*AppInfo, 0, len(apps))
	for _, app := range apps {
		result = append(result, AppJSON(app))
	}
	return result
}

// ---------------------------------------------------------------------------
// 用户资料
// ---------------------------------------------------------------------------

// UsersJSON 按调用方权限与目标用户的 visibilities 过滤用户资料，供资料、搜索与关系列表接口复用。
// real_name 采用字段级可见性：他人资料需 real_name.allowed 权限，再按 public/friends/private 判定是否返回。
func UsersJSON(ctx context.Context, claims *model.RegisteredTokenClaims, targetUsers ...*model.User) ([]gin.H, *errs.Error) {
	if claims == nil {
		return nil, errs.InvalidTokenError().AppendDetails("令牌格式错误").Seal()
	}

	// 读取调用方对「自己」与「他人」的资料字段权限
	selfBasic := permsvc.HasPermission(claims, permsvc.PermUserProfileReadBasic)
	selfIdentity := permsvc.HasPermission(claims, permsvc.PermUserProfileReadIdentity)
	selfRealName := permsvc.HasPermission(claims, permsvc.PermUserProfileReadRealName)
	selfAbout := permsvc.HasPermission(claims, permsvc.PermUserProfileReadAbout)
	selfVisibilities := permsvc.HasPermission(claims, permsvc.PermUserProfileReadVisibilities)

	otherBasic := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadBasic)
	otherIdentity := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadIdentity)
	otherRealName := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadRealName)
	otherRealNameAllowed := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadRealNameAllowed)
	otherAbout := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadAbout)
	otherVisibilities := permsvc.HasPermission(claims, permsvc.PermUsersProfileReadVisibilities)

	isAdmin := HasUsersNamespacePerm(claims)

	// 逐用户判定可读字段并组装响应；即使无任何字段可读也会返回 id
	results := make([]gin.H, 0, len(targetUsers))
	for _, targetUser := range targetUsers {
		// 已注销用户仅向非管理员返回最小化标识。
		if targetUser.DeletedAt.Valid && !isAdmin {
			results = append(results, gin.H{
				"username": targetUser.Username,
				"deleted":  true,
			})
			continue
		}

		isSelf := claims.UserID == targetUser.ID

		var basic, identity, realName, about, visibilities bool
		if isSelf {
			// 管理自己时 self.* 与 users.* 权限取并集，管理员通常只被授予 users.*。
			basic = selfBasic || otherBasic
			identity = selfIdentity || otherIdentity
			realName = selfRealName || otherRealName || otherRealNameAllowed
			about = selfAbout || otherAbout
			visibilities = selfVisibilities || otherVisibilities
		} else {
			basic, identity, about, visibilities = otherBasic, otherIdentity, otherAbout, otherVisibilities
			if otherRealName {
				realName = true
			} else if !otherRealNameAllowed {
				realName = false
			} else {
				switch targetUser.Visibilities.RealName {
				case model.VisibilityPublic:
					realName = true
				case model.VisibilityFriends:
					rel, err := usersvc.GetFollowRelationship(ctx, claims.UserID, targetUser.ID)
					if err != nil {
						return nil, err
					}
					realName = rel == model.RelationshipFriends
				default:
					realName = false
				}
			}
		}

		res := gin.H{"id": targetUser.ID}
		if basic {
			res["username"] = targetUser.Username
			res["nickname"] = targetUser.Nickname
			res["deleted"] = targetUser.DeletedAt.Valid
		}
		if identity {
			res["type"] = targetUser.Type
			res["school"] = targetUser.School
			res["student_num"] = targetUser.StudentNum
		}
		if realName {
			res["real_name"] = targetUser.RealName
		}
		if about {
			res["signature"] = targetUser.Signature
			res["bio"] = targetUser.Bio
		}
		if visibilities {
			res["visibilities"] = targetUser.Visibilities
		}
		if isAdmin {
			res["password_reset_required"] = targetUser.PasswordResetRequired
		}
		results = append(results, res)
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// 权限定义
// ---------------------------------------------------------------------------

func DefJSON(def *model.PermissionDef, namespace string) gin.H {
	return gin.H{
		"id":          def.ID,
		"app_id":      def.AppID,
		"namespace":   namespace,
		"permission":  permsvc.Render(namespace, def.Value),
		"value":       def.Value,
		"description": def.Description,
		"requestable": def.Requestable,
		"created_by":  def.CreatedBy,
		"created_at":  def.CreatedAt,
		"updated_at":  def.UpdatedAt,
	}
}

func DefsJSON(defs []*model.PermissionDef, namespace string) []gin.H {
	data := make([]gin.H, 0, len(defs))
	for _, def := range defs {
		data = append(data, DefJSON(def, namespace))
	}
	return data
}

// ImplicationJSON 渲染一条权限继承边及其授权记录。
func ImplicationJSON(implication *userpermsvc.PermissionImplication, namespace string) gin.H {
	return gin.H{
		"permission": DefJSON(implication.Permission, namespace),
		"grant": gin.H{
			"granted_by_user_id": implication.Grant.GrantedByUserID,
			"valid_from":         implication.Grant.ValidFrom,
			"valid_until":        implication.Grant.ValidUntil,
			"note":               implication.Grant.Note,
			"created_at":         implication.Grant.CreatedAt,
			"updated_at":         implication.Grant.UpdatedAt,
		},
	}
}

func ImplicationsJSON(implications []*userpermsvc.PermissionImplication, namespace string) []gin.H {
	data := make([]gin.H, 0, len(implications))
	for _, implication := range implications {
		data = append(data, ImplicationJSON(implication, namespace))
	}
	return data
}

// ---------------------------------------------------------------------------
// 用户组与直接授权
// ---------------------------------------------------------------------------

func GroupJSON(role *model.Role) gin.H {
	return gin.H{
		"id":         role.ID,
		"app_id":     role.AppID,
		"name":       role.Name,
		"note":       role.Note,
		"public":     role.Public,
		"system":     role.System,
		"created_at": role.CreatedAt,
		"updated_at": role.UpdatedAt,
	}
}

func GroupSearchJSON(role *model.Role, namespace string) gin.H {
	data := GroupJSON(role)
	data["app_namespace"] = namespace
	return data
}

func RolePermissionJSON(grant *model.RolePermission) gin.H {
	return gin.H{
		"permission":         grant.Permission,
		"granted_by_user_id": grant.GrantedByUserID,
		"valid_from":         grant.ValidFrom,
		"valid_until":        grant.ValidUntil,
		"note":               grant.Note,
		"created_at":         grant.CreatedAt,
		"updated_at":         grant.UpdatedAt,
	}
}

func GroupUserJSON(member *userpermsvc.RoleUser) gin.H {
	return gin.H{
		"user_id":     member.UserID,
		"username":    member.Username,
		"nickname":    member.Nickname,
		"deleted":     member.Deleted,
		"granted_by":  member.GrantedBy,
		"valid_from":  member.ValidFrom,
		"valid_until": member.ValidUntil,
		"created_at":  member.CreatedAt,
	}
}

func GroupUsersJSON(users []*userpermsvc.RoleUser) []gin.H {
	data := make([]gin.H, 0, len(users))
	for _, member := range users {
		data = append(data, GroupUserJSON(member))
	}
	return data
}

func GrantJSON(grant *model.UserPermissionGrant) gin.H {
	return gin.H{
		"id":                 grant.ID,
		"user_id":            grant.UserID,
		"permission":         grant.Permission,
		"granted_by_user_id": grant.GrantedByUserID,
		"granted_by_app_id":  grant.GrantedByAppID,
		"valid_from":         grant.ValidFrom,
		"valid_until":        grant.ValidUntil,
		"note":               grant.Note,
		"created_at":         grant.CreatedAt,
		"updated_at":         grant.UpdatedAt,
	}
}

func GrantsJSON(grants []*model.UserPermissionGrant) []gin.H {
	data := make([]gin.H, 0, len(grants))
	for _, grant := range grants {
		data = append(data, GrantJSON(grant))
	}
	return data
}

// ---------------------------------------------------------------------------
// 登录会话
// ---------------------------------------------------------------------------

// SessionInfo 会话列表的响应项；不返回令牌哈希等敏感字段。
type SessionInfo struct {
	UUID          string     `json:"uuid"`
	IsCurrent     bool       `json:"is_current"`   // 是否为当前请求令牌所属的登录会话
	IsTemporary   bool       `json:"is_temporary"` // 临时会话刷新时不会延长有效期
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	LastIP        *string    `json:"last_ip"`
	LastUserAgent string     `json:"last_user_agent"`
}

// SessionInfos 把会话记录转换为响应项；currentID 为空时（查看他人会话）不标记当前会话。
func SessionInfos(sessions []*model.UserSession, currentID *uuid.UUID) []SessionInfo {
	results := make([]SessionInfo, 0, len(sessions))
	for _, session := range sessions {
		results = append(results, SessionInfo{
			UUID:          session.UUID.String(),
			IsCurrent:     currentID != nil && session.UUID == *currentID,
			IsTemporary:   session.IsTemporary,
			CreatedAt:     session.CreatedAt,
			UpdatedAt:     session.UpdatedAt,
			ExpiresAt:     session.ExpiresAt,
			LastUsedAt:    session.LastUsedAt,
			LastIP:        session.LastIP,
			LastUserAgent: session.LastUserAgent,
		})
	}
	return results
}

// ---------------------------------------------------------------------------
// 注册申请
// ---------------------------------------------------------------------------

func RegisterRequestJSON(request *model.RegisterRequest) gin.H {
	return gin.H{
		"id":               request.ID,
		"type":             request.Type,
		"student_num":      request.StudentNum,
		"real_name":        request.RealName,
		"school":           request.School,
		"username":         request.Username,
		"nickname":         request.Nickname,
		"created_at":       request.CreatedAt,
		"status":           request.Status,
		"created_user_id":  request.CreatedUserID,
		"reviewer_user_id": request.ReviewerUserID,
		"review_comment":   request.ReviewComment,
		"reviewed_at":      request.ReviewedAt,
	}
}

func RegisterRequestStatusJSON(request *model.RegisterRequest) gin.H {
	return gin.H{
		"status":         request.Status,
		"review_comment": request.ReviewComment,
		"reviewed_at":    request.ReviewedAt,
	}
}

// ---------------------------------------------------------------------------
// 用户关系
// ---------------------------------------------------------------------------

func RelationshipJSON(relationship model.Relationship) gin.H {
	return gin.H{"relationship": relationship}
}

// ---------------------------------------------------------------------------
// 用户封禁
// ---------------------------------------------------------------------------

func BanJSON(ban *model.UserBan) gin.H {
	if ban == nil {
		return gin.H{"banned": false}
	}
	return gin.H{
		"banned":   true,
		"reason":   ban.Reason,
		"end_time": ban.EndTime,
	}
}
