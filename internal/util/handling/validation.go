package handling

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	"mime/multipart"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/google/uuid"
)

const (
	MaxAppRedirectURIs      = 10   // 单个应用允许配置的回调地址数量
	MaxAppRequestedPerms    = 100  // 单个应用允许申请的权限数量
	MaxAppURLLength         = 512  // 回调地址与主页地址的最大长度
	MaxAppNameLength        = 128  // 应用名称最大字符数
	MaxAppDescriptionLength = 2048 // 应用描述最大字符数
	MaxPermissionLength     = 128  // 完整权限串的最大字符数
	MaxReviewCommentLength  = 1024 // 注册申请审核意见最大字符数
)

// 各类输入的格式校验规则。统一使用 regexp2 的 \A...\z 全串匹配。
var (
	// regexUsername 用户名：4-32 位字母、数字、下划线或连字符。
	regexUsername = regexp2.MustCompile(`\A[a-zA-Z0-9_-]{4,32}\z`, regexp2.None)
	// regexNickname 昵称：1-32 个字符（不限制内容）。
	regexNickname = regexp2.MustCompile(`\A.{1,32}\z`, regexp2.None)
	// regexRealName 姓名：1-4 个汉字，允许间隔号「·」（少数民族姓名）。
	regexRealName = regexp2.MustCompile(`\A[\u4e00-\u9fff\u00b7]{1,4}\z`, regexp2.None)
	// regexStudentNum 学号：8 位数字，或青分学号（6 位数字 + 0 + 2 位数字，共 9 位）。
	regexStudentNum = regexp2.MustCompile(`\A(?:\d{8}|\d{6}0\d{2})\z`, regexp2.None)
	// regexEmail 邮箱：限制总长 254，采用 RFC 5322 的宽松子集。
	regexEmail = regexp2.MustCompile(`\A(?=[\s\S]{1,254}\z)([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"(\[\]!#-[^-~ \t]|(\\[\t -~]))+\")@([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\[[\t -Z^-~]*])\z`, regexp2.None)
	// regexPassword 密码：8-32 位，至少包含大写字母、小写字母和数字，允许常见符号。
	regexPassword = regexp2.MustCompile(`\A(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\x60~]{8,32}\z`, regexp2.None)
	// regexTOTPCode TOTP 验证码：6 位数字。
	regexTOTPCode = regexp2.MustCompile(`\A\d{6}\z`, regexp2.None)
	// regexQQ QQ 号：5-12 位、非 0 开头的数字。
	regexQQ = regexp2.MustCompile(`\A[1-9]\d{4,11}\z`, regexp2.None)
)

// emailBlockedDomains 禁止注册/绑定使用的邮箱域名（校内域名不允许作为联系方式）。
var emailBlockedDomains = map[string]struct{}{
	"fdfz.top": {},
}

// imageMIMETypes 是允许上传的图片类型，不含可携带脚本的 SVG。
var imageMIMETypes = map[string]struct{}{
	"image/jpeg": {},
	"image/png":  {},
	"image/webp": {},
}

// containsNUL 判断字符串是否包含 NUL 字节；PostgreSQL 的 text 无法存储 NUL，需提前拒绝。
func containsNUL(s string) bool {
	return strings.IndexByte(s, 0) >= 0
}

// ValidateUsername 校验用户名格式；为空时视为未提供。
func ValidateUsername(username string) *errs.Error {
	if username == "" {
		return errs.BadRequestError().AppendDetails("未提供用户名")
	}
	if ok, err := regexUsername.MatchString(username); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate username").AppendDetails("用户名校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("用户名格式错误")
	}
	return nil
}

// ValidateNickname 校验昵称格式；为空时视为未提供。
func ValidateNickname(nickname string) *errs.Error {
	if nickname == "" {
		return errs.BadRequestError().AppendDetails("未提供昵称")
	}
	if containsNUL(nickname) {
		return errs.BadRequestError().AppendDetails("昵称格式错误")
	}
	if ok, err := regexNickname.MatchString(nickname); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate nickname").AppendDetails("昵称校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("昵称格式错误")
	}
	return nil
}

// ValidateRealName 校验真实姓名格式；为空时视为未提供。
func ValidateRealName(realName string) *errs.Error {
	if realName == "" {
		return errs.BadRequestError().AppendDetails("未提供姓名")
	}
	if ok, err := regexRealName.MatchString(realName); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate real name").AppendDetails("姓名校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("姓名格式错误")
	}
	return nil
}

// ValidateStudentNum 校验学号格式；为空时视为未提供。
func ValidateStudentNum(studentNum string) *errs.Error {
	if studentNum == "" {
		return errs.BadRequestError().AppendDetails("未提供学号")
	}
	if ok, err := regexStudentNum.MatchString(studentNum); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate student num").AppendDetails("学号校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("学号格式错误")
	}
	return nil
}

// ValidateEmail 校验邮箱格式，并拒绝使用校内域名（emailBlockedDomains）。
func ValidateEmail(email string) *errs.Error {
	if email == "" {
		return errs.BadRequestError().AppendDetails("未提供邮箱")
	}
	if ok, err := regexEmail.MatchString(email); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate email").AppendDetails("邮箱校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("邮箱格式错误")
	}

	// 取解析后地址最后一个 '@' 之后的域名：带引号的 local-part 可包含 '@'。
	address := email
	if parsed, err := mail.ParseAddress(email); err == nil {
		address = parsed.Address
	}
	if at := strings.LastIndexByte(address, '@'); at >= 0 {
		domain := strings.ToLower(strings.TrimSpace(address[at+1:]))
		domain = strings.TrimSuffix(domain, ".")
		for blocked := range emailBlockedDomains {
			if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
				return errs.BadRequestError().AppendDetails("不能使用该邮箱域名")
			}
		}
	}

	return nil
}

// ValidateQQ 校验 QQ 号格式；为空时视为未提供。
func ValidateQQ(qq string) *errs.Error {
	if qq == "" {
		return errs.BadRequestError().AppendDetails("未提供 QQ 号")
	}
	if ok, err := regexQQ.MatchString(qq); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate QQ").AppendDetails("QQ 号校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("QQ 号格式错误")
	}
	return nil
}

// ValidatePassword 校验密码强度（长度与字符种类）。
func ValidatePassword(password string) *errs.Error {
	if password == "" {
		return errs.BadRequestError().AppendDetails("未提供密码")
	}
	if ok, err := regexPassword.MatchString(password); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate password").AppendDetails("密码校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("密码格式错误")
	}
	return nil
}

// ValidateMIMEType 校验 MIME 类型白名单，仅返回错误；检测会消耗文件读取偏移，调用后不可复用。
func ValidateMIMEType(fileHeader *multipart.FileHeader, allowedTypes map[string]struct{}) *errs.Error {
	_, err := DetectMIMEType(fileHeader, allowedTypes)
	return err
}

// ValidateSchool 校验学校枚举取值。
func ValidateSchool(school model.School) *errs.Error {
	if !school.IsValid() {
		return errs.BadRequestError().AppendDetails("学校取值错误")
	}
	return nil
}

// ValidateUserType 校验用户类型枚举取值。
func ValidateUserType(typ model.UserType) *errs.Error {
	if !typ.IsValid() {
		return errs.BadRequestError().AppendDetails("用户类型取值错误")
	}
	return nil
}

// ValidateVisibility 校验资料可见性枚举取值。
func ValidateVisibility(visibility model.Visibility) *errs.Error {
	if !visibility.IsValid() {
		return errs.BadRequestError().AppendDetails("可见性取值错误")
	}
	return nil
}

// ValidateSignature 校验个性签名长度（允许为空）。
func ValidateSignature(signature string) *errs.Error {
	if containsNUL(signature) {
		return errs.BadRequestError().AppendDetails("个性签名格式错误")
	}
	if utf8.RuneCountInString(signature) > 128 {
		return errs.BadRequestError().AppendDetails("个性签名过长")
	}
	return nil
}

// ValidateBio 校验个人简介长度（允许为空）。
func ValidateBio(bio string) *errs.Error {
	if containsNUL(bio) {
		return errs.BadRequestError().AppendDetails("个人简介格式错误")
	}
	if utf8.RuneCountInString(bio) > 2048 {
		return errs.BadRequestError().AppendDetails("个人简介过长")
	}
	return nil
}

// ValidateBanReason 校验封禁原因：不能为空白，最长 256 个字符。
func ValidateBanReason(reason string) *errs.Error {
	if strings.TrimSpace(reason) == "" {
		return errs.BadRequestError().AppendDetails("未提供封禁原因")
	}
	if containsNUL(reason) {
		return errs.BadRequestError().AppendDetails("封禁原因格式错误")
	}
	if utf8.RuneCountInString(reason) > 256 {
		return errs.BadRequestError().AppendDetails("封禁原因过长")
	}
	return nil
}

// ValidateTOTPCode 校验 TOTP 验证码格式（6 位数字）；为空时视为未提供。
func ValidateTOTPCode(code string) *errs.Error {
	if code == "" {
		return errs.BadRequestError().AppendDetails("未提供 TOTP 验证码")
	}
	if ok, err := regexTOTPCode.MatchString(code); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate totp code").AppendDetails("TOTP 验证码校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("TOTP 验证码格式错误")
	}
	return nil
}

// ValidatePermissionValue 校验权限值（不含命名空间的节点串）：不能为空，最长 96 个字符。
func ValidatePermissionValue(value string) *errs.Error {
	if value == "" {
		return errs.BadRequestError().AppendDetails("未提供权限值")
	}
	if containsNUL(value) {
		return errs.BadRequestError().AppendDetails("权限值格式错误")
	}
	if utf8.RuneCountInString(value) > 96 {
		return errs.BadRequestError().AppendDetails("权限值过长")
	}
	return nil
}

// ValidatePermissionDescription 校验权限描述长度（允许为空）。
func ValidatePermissionDescription(description string) *errs.Error {
	if containsNUL(description) {
		return errs.BadRequestError().AppendDetails("权限描述格式错误")
	}
	if utf8.RuneCountInString(description) > 256 {
		return errs.BadRequestError().AppendDetails("权限描述过长")
	}
	return nil
}

// ValidateUserGroupName 校验用户组名称：不能为空，最长 128 个字符。
func ValidateUserGroupName(name string) *errs.Error {
	if name == "" {
		return errs.BadRequestError().AppendDetails("未提供用户组名")
	}
	if containsNUL(name) {
		return errs.BadRequestError().AppendDetails("用户组名格式错误")
	}
	if utf8.RuneCountInString(name) > 128 {
		return errs.BadRequestError().AppendDetails("用户组名过长")
	}
	return nil
}

// ValidateUserGroupNote 校验用户组备注长度（允许为空）。
func ValidateUserGroupNote(note string) *errs.Error {
	if containsNUL(note) {
		return errs.BadRequestError().AppendDetails("用户组备注格式错误")
	}
	if utf8.RuneCountInString(note) > 256 {
		return errs.BadRequestError().AppendDetails("用户组备注过长")
	}
	return nil
}

// ValidateGrantPermission 校验授权使用的完整权限串（含命名空间）。
func ValidateGrantPermission(permission string) *errs.Error {
	if permission == "" {
		return errs.BadRequestError().AppendDetails("未提供权限")
	}
	if _, err := permsvc.ParsePermission(permission); err != nil {
		return errs.BadRequestError().AppendDetails("权限格式错误")
	}
	if utf8.RuneCountInString(permission) > MaxPermissionLength {
		return errs.BadRequestError().AppendDetails("权限过长")
	}
	return nil
}

// ValidateGrantNote 校验授权备注长度（允许为空）。
func ValidateGrantNote(note string) *errs.Error {
	if containsNUL(note) {
		return errs.BadRequestError().AppendDetails("授权备注格式错误")
	}
	if utf8.RuneCountInString(note) > 256 {
		return errs.BadRequestError().AppendDetails("授权备注过长")
	}
	return nil
}

// ValidateValidRange 校验授权有效期区间：validUntil 必须晚于 validFrom。
func ValidateValidRange(validFrom, validUntil *time.Time) *errs.Error {
	if validFrom != nil && validUntil != nil && !validUntil.After(*validFrom) {
		return errs.BadRequestError().AppendDetails("有效期范围错误")
	}
	return nil
}

// ValidateAppNamespace 校验应用命名空间：小写字母开头、2-32 位。
func ValidateAppNamespace(namespace string) *errs.Error {
	if namespace == "" {
		return errs.BadRequestError().AppendDetails("未提供命名空间")
	}
	if ok, err := permsvc.RegexNamespace.MatchString(namespace); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate app namespace").AppendDetails("命名空间校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("命名空间格式错误")
	}
	return nil
}

func ValidateAppName(name string) *errs.Error {
	if strings.TrimSpace(name) == "" {
		return errs.BadRequestError().AppendDetails("未提供应用名称")
	}
	if containsNUL(name) {
		return errs.BadRequestError().AppendDetails("应用名称格式错误")
	}
	if utf8.RuneCountInString(name) > MaxAppNameLength {
		return errs.BadRequestError().AppendDetails("应用名称过长")
	}
	return nil
}

func ValidateAppDescription(description string) *errs.Error {
	if containsNUL(description) {
		return errs.BadRequestError().AppendDetails("应用描述格式错误")
	}
	if utf8.RuneCountInString(description) > MaxAppDescriptionLength {
		return errs.BadRequestError().AppendDetails("应用描述过长")
	}
	return nil
}

func validateAppHTTPURL(raw, item string) *errs.Error {
	if raw == "" {
		return errs.BadRequestError().AppendDetails("未提供" + item)
	}
	if containsNUL(raw) {
		return errs.BadRequestError().AppendDetails(item + "格式错误")
	}
	if utf8.RuneCountInString(raw) > MaxAppURLLength {
		return errs.BadRequestError().AppendDetails(item + "过长")
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return errs.BadRequestError().AppendDetails(item + "格式错误")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errs.BadRequestError().AppendDetails(item + "必须使用 http 或 https")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errs.BadRequestError().AppendDetails(item + "格式错误")
	}
	return nil
}

func ValidateAppHomepageURL(homepageURL string) *errs.Error {
	if homepageURL == "" {
		return nil
	}
	return validateAppHTTPURL(homepageURL, "主页地址")
}

func ValidateAppClientType(clientType model.AppType) *errs.Error {
	if !clientType.IsValid() {
		return errs.BadRequestError().AppendDetails("客户端类型取值错误")
	}
	return nil
}

func ValidateAppRedirectURIs(redirectURIs []string) *errs.Error {
	if len(redirectURIs) > MaxAppRedirectURIs {
		return errs.BadRequestError().AppendDetails("回调地址数量过多")
	}
	for _, redirectURI := range redirectURIs {
		if err := validateAppHTTPURL(redirectURI, "回调地址"); err != nil {
			return err
		}
	}
	return nil
}

func ValidateAppRequestedPermissions(permissions []string) *errs.Error {
	if len(permissions) > MaxAppRequestedPerms {
		return errs.BadRequestError().AppendDetails("申请权限数量过多")
	}
	for _, permission := range permissions {
		if _, err := permsvc.ParsePermission(permission); err != nil {
			return errs.BadRequestError().AppendDetails("权限格式错误")
		}
		if utf8.RuneCountInString(permission) > MaxPermissionLength {
			return errs.BadRequestError().AppendDetails("权限过长")
		}
	}
	return nil
}

// ValidateAppOwnerID 校验应用所有者 ID；用户是否存在由调用方确认。
func ValidateAppOwnerID(ownerUserID int64) *errs.Error {
	if ownerUserID <= 0 {
		return errs.BadRequestError().AppendDetails("未提供应用所有者")
	}
	return nil
}

func ValidateImageUpload(files []*multipart.FileHeader, item string) (*multipart.FileHeader, string, string, *errs.Error) {
	switch {
	case len(files) == 0:
		return nil, "", "", errs.BadRequestError().AppendDetails("未提供" + item)
	case len(files) > 1:
		return nil, "", "", errs.BadRequestError().AppendDetails(item + "最多上传 1 张")
	}

	fileHeader := files[0]
	mimeType, err := DetectMIMEType(fileHeader, imageMIMETypes)
	if err != nil {
		return nil, "", "", err
	}
	extension := ImageExtension(mimeType)
	if extension == "" {
		return nil, "", "", errs.UnsupportedMediaTypeError().AppendDetails("文件类型不受支持")
	}
	return fileHeader, mimeType, extension, nil
}

// ValidateUserID 校验用户 ID；用户是否存在由调用方确认。
func ValidateUserID(userID int64) *errs.Error {
	if userID <= 0 {
		return errs.BadRequestError().AppendDetails("用户 ID 格式错误")
	}
	return nil
}

func ValidateFutureTime(t time.Time, item string) *errs.Error {
	if !t.After(time.Now()) {
		return errs.BadRequestError().AppendDetails(item + "必须晚于当前时间")
	}
	return nil
}

// ValidateVerificationCode 只校验验证码非空，格式由各流程自行判断。
func ValidateVerificationCode(code string) *errs.Error {
	if code == "" {
		return errs.BadRequestError().AppendDetails("未提供验证码")
	}
	return nil
}

// ValidateAppPermissionPattern 校验权限模式串（允许 * / ** 通配）属于指定应用命名空间。
func ValidateAppPermissionPattern(permission, namespace string) *errs.Error {
	if permission == "" {
		return errs.BadRequestError().AppendDetails("未提供权限")
	}
	parsed, err := permsvc.ParsePattern(permission)
	if err != nil {
		return errs.BadRequestError().AppendDetails("权限格式错误")
	}
	if utf8.RuneCountInString(permission) > MaxPermissionLength {
		return errs.BadRequestError().AppendDetails("权限过长")
	}
	if parsed.Namespace != namespace {
		return errs.BadRequestError().AppendDetails("权限不属于该应用")
	}
	return nil
}

// ParseAppPermissionValue 解析属于指定命名空间的权限串，返回不含命名空间的权限值。
func ParseAppPermissionValue(permission, namespace string) (string, *errs.Error) {
	parsed, err := permsvc.ParsePermission(permission)
	if err != nil {
		return "", errs.BadRequestError().AppendDetails("权限格式错误")
	}
	if parsed.Namespace != namespace {
		return "", errs.BadRequestError().AppendDetails("权限命名空间不可用")
	}
	value := strings.Join(parsed.Nodes, ".")
	if err := ValidatePermissionValue(value); err != nil {
		return "", err
	}
	return value, nil
}

// ValidateRegisterStudentNum 校验注册表单中学号与用户类型的组合，并校验学生学号格式。
func ValidateRegisterStudentNum(userType model.UserType, studentNum string) *errs.Error {
	if userType != model.UserTypeStudent {
		if studentNum != "" {
			return errs.BadRequestError().AppendDetails("非学生账号不能提供学号")
		}
		return nil
	}
	if studentNum == "" {
		return errs.BadRequestError().AppendDetails("学生账号未提供学号")
	}
	return ValidateStudentNum(studentNum)
}

// ValidateRegisterReviewStatus 校验注册申请审核状态：只能是 approved 或 rejected。
func ValidateRegisterReviewStatus(status model.RegisterRequestStatus) *errs.Error {
	if !status.IsValid() || status == model.RegisterRequestStatusPending {
		return errs.BadRequestError().AppendDetails("审核状态取值错误")
	}
	return nil
}

func ValidateRegisterReviewComment(comment string) *errs.Error {
	if containsNUL(comment) {
		return errs.BadRequestError().AppendDetails("审核意见格式错误")
	}
	if utf8.RuneCountInString(comment) > MaxReviewCommentLength {
		return errs.BadRequestError().AppendDetails("审核意见过长")
	}
	return nil
}

func ValidateUUID(id uuid.UUID, item string) *errs.Error {
	if id == uuid.Nil {
		return errs.BadRequestError().AppendDetails("未提供" + item)
	}
	return nil
}

func ParseUUID(raw, item string) (uuid.UUID, *errs.Error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, errs.BadRequestError().AppendDetails(item + "格式错误")
	}
	return id, nil
}
