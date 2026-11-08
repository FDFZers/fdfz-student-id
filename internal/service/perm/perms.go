package perm

// 本文件列出内置 student_id 应用（FDFZ 学生身份后端自身）使用的权限串常量。
// 这些常量对应数据库 permission_defs 中的权限定义，供中间件与处理器做鉴权判断。
// 注意：常量值必须与已有权限定义保持一致，改动会直接影响各接口的鉴权结果。

// 注册申请
const (
	PermRegisterRequestList   = "student_id:register_requests.list"
	PermRegisterRequestRead   = "student_id:register_requests.read"
	PermRegisterRequestReview = "student_id:register_requests.review"
)

// 用户（user 为当前登录用户本人，users 为管理员视角的其他用户）
const (
	PermUsersList   = "student_id:users.list"
	PermUsersDelete = "student_id:users.delete"

	PermUserProfileReadBasic          = "student_id:user.profile.read.basic"
	PermUserProfileReadIdentity       = "student_id:user.profile.read.identity"
	PermUserProfileReadRealName       = "student_id:user.profile.read.real_name"
	PermUserProfileReadAbout          = "student_id:user.profile.read.about"
	PermUserProfileReadVisibilities   = "student_id:user.profile.read.visibilities"
	PermUserProfileUpdateBasic        = "student_id:user.profile.update.basic"
	PermUserProfileUpdateAbout        = "student_id:user.profile.update.about"
	PermUserProfileUpdateVisibilities = "student_id:user.profile.update.visibilities"

	PermUsersProfileReadBasic           = "student_id:users.profile.read.basic"
	PermUsersProfileReadIdentity        = "student_id:users.profile.read.identity"
	PermUsersProfileReadRealNameAllowed = "student_id:users.profile.read.real_name.allowed"
	PermUsersProfileReadRealName        = "student_id:users.profile.read.real_name"
	PermUsersProfileReadAbout           = "student_id:users.profile.read.about"
	PermUsersProfileReadVisibilities    = "student_id:users.profile.read.visibilities"
	PermUsersProfileUpdateBasic         = "student_id:users.profile.update.basic"
	PermUsersProfileUpdateIdentity      = "student_id:users.profile.update.identity"
	PermUsersProfileUpdateAbout         = "student_id:users.profile.update.about"
	PermUsersProfileUpdateVisibilities  = "student_id:users.profile.update.visibilities"
)

// 用户封禁
const (
	PermUserBanRead   = "student_id:user.ban.read"
	PermUsersBanRead  = "student_id:users.ban.read"
	PermUsersBanWrite = "student_id:users.ban.write"
)

// 用户会话
const (
	PermUserSessionRead  = "student_id:user.session.read"
	PermUserSessionWrite = "student_id:user.session.write"

	PermUsersSessionRead  = "student_id:users.session.read"
	PermUsersSessionWrite = "student_id:users.session.write"
)

// 用户关注
const (
	PermUserRelationRead  = "student_id:user.relation.read"
	PermUserRelationWrite = "student_id:user.relation.write"

	PermUsersRelationRead        = "student_id:users.relation.read"
	PermUsersRelationReadAllowed = "student_id:users.relation.read.allowed"
	PermUsersRelationWrite       = "student_id:users.relation.write"
)

// 权限管理（全局权限，以及按「是否拥有应用」放权的 owned_apps 权限）
const (
	PermPermissionsRead  = "student_id:permissions.read"
	PermPermissionsWrite = "student_id:permissions.write"

	PermPermissionsReadOwnedApps  = "student_id:permissions.read.owned_apps"
	PermPermissionsWriteOwnedApps = "student_id:permissions.write.owned_apps"
)
