package perm

// 注册申请
const (
	PermRegisterRequestList   = "student_id:register_requests.list"
	PermRegisterRequestRead   = "student_id:register_requests.read"
	PermRegisterRequestReview = "student_id:register_requests.review"
)

// 用户
const (
	PermUsersList          = "student_id:users.list"
	PermUsersCreate        = "student_id:users.create"
	PermUsersDelete        = "student_id:users.delete"
	PermUsersPasswordWrite = "student_id:users.password.write"

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

// 绑定信息
const (
	PermBindingReadStatus = "student_id:binding.read.status"
	PermBindingReadEmail  = "student_id:binding.read.email"
	PermBindingReadQQ     = "student_id:binding.read.qq"

	PermBindingsReadStatus = "student_id:bindings.read.status"
	PermBindingsReadEmail  = "student_id:bindings.read.email"
	PermBindingsReadQQ     = "student_id:bindings.read.qq"
	PermBindingsWrite      = "student_id:bindings.write"
)

// 权限管理
const (
	PermPermissionRead   = "student_id:permission.read"
	PermPermissionWrite  = "student_id:permission.write"
	PermPermissionsRead  = "student_id:permissions.read"
	PermPermissionsWrite = "student_id:permissions.write"
)

// 应用管理
const (
	PermAppRead   = "student_id:app.read"
	PermAppUpdate = "student_id:app.update"
	PermAppDelete = "student_id:app.delete"

	PermAppsList    = "student_id:apps.list"
	PermAppsCreate  = "student_id:apps.create"
	PermAppsUpdate  = "student_id:apps.update"
	PermAppsSuspend = "student_id:apps.suspend"
	PermAppsDelete  = "student_id:apps.delete"
)

// OAuth 授权管理
const (
	PermOAuthRead    = "student_id:oauth.read"
	PermOAuthRevoke  = "student_id:oauth.revoke"
	PermOAuthsRead   = "student_id:oauths.read"
	PermOAuthsRevoke = "student_id:oauths.revoke"
)

const (
	PermNotificationRead  = "student_id:notification.read"
	PermNotificationWrite = "student_id:notification.write"

	PermNotificationsSend = "student_id:notifications.send"
	PermNotificationsRead = "student_id:notifications.read"
)
