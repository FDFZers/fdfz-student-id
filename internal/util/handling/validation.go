package handling

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

var regexUsername = regexp2.MustCompile(`\A[a-zA-Z0-9_-]{4,32}\z`, regexp2.None)
var regexNickname = regexp2.MustCompile(`\A.{1,32}\z`, regexp2.None)
var regexRealName = regexp2.MustCompile(`\A[\u4e00-\u9fff\u00b7]{1,4}\z`, regexp2.None)
var regexStudentNum = regexp2.MustCompile(`\A(?:\d{8}|\d{6}0\d{2})\z`, regexp2.None) // 青分学号9位
var regexEmail = regexp2.MustCompile(`\A(?=[\s\S]{1,254}\z)([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"(\[\]!#-[^-~ \t]|(\\[\t -~]))+\")@([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\[[\t -Z^-~]*])\z`, regexp2.None)
var regexPassword = regexp2.MustCompile(`\A(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\x60~]{8,32}\z`, regexp2.None)
var regexTOTPCode = regexp2.MustCompile(`\A\d{6}\z`, regexp2.None)
var regexQQ = regexp2.MustCompile(`\A[1-9]\d{4,11}\z`, regexp2.None) // 5-12 位非 0 开头数字
var emailBlockedDomains = map[string]struct{}{
	"fdfz.top": {},
}

func ValidateUsername(username string) *errs.Error {
	if ok, err := regexUsername.MatchString(username); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate username").AppendDetails("用户名校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的用户名")
	}
	return nil
}

func ValidateNickname(nickname string) *errs.Error {
	if ok, err := regexNickname.MatchString(nickname); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate nickname").AppendDetails("昵称校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的昵称")
	}
	return nil
}

func ValidateRealName(realName string) *errs.Error {
	if ok, err := regexRealName.MatchString(realName); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate real name").AppendDetails("姓名校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的姓名")
	}
	return nil
}

func ValidateStudentNum(studentNum string) *errs.Error {
	if ok, err := regexStudentNum.MatchString(studentNum); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate student num").AppendDetails("学号校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的学号")
	}
	return nil
}

func ValidateEmail(email string) *errs.Error {
	if ok, err := regexEmail.MatchString(email); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate email").AppendDetails("邮箱校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的邮箱")
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		domain := strings.ToLower(parts[1])
		if _, ok := emailBlockedDomains[domain]; ok {
			return errs.BadRequestError().AppendDetails("无法使用此邮箱域名")
		}
	}

	return nil
}

func ValidateQQ(qq string) *errs.Error {
	if ok, err := regexQQ.MatchString(qq); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate QQ").AppendDetails("QQ 号校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的 QQ 号")
	}
	return nil
}

func ValidatePassword(password string) *errs.Error {
	if ok, err := regexPassword.MatchString(password); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate password").AppendDetails("密码校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的密码")
	}
	return nil
}

func ValidateMIMEType(fileHeader *multipart.FileHeader, allowedTypes map[string]struct{}) *errs.Error {
	file, err := fileHeader.Open()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to open file while detecting mime").AppendDetails("文件类型检测失败")
	}
	defer func(file multipart.File) {
		_ = file.Close()
	}(file)

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to read file while detecting mime").AppendDetails("文件类型检测失败")
	}

	fileType := http.DetectContentType(buffer)

	if _, ok := allowedTypes[fileType]; !ok {
		return errs.UnsupportedMediaTypeError().AppendDetails("无效的文件类型")
	}

	return nil
}

func ValidateSchool(school model.School) *errs.Error {
	if !school.IsValid() {
		return errs.BadRequestError().AppendDetails("无效的学校")
	}
	return nil
}

func ValidateUserType(typ model.UserType) *errs.Error {
	if !typ.IsValid() {
		return errs.BadRequestError().AppendDetails("无效的用户类型")
	}
	return nil
}

func ValidateVisibility(visibility model.Visibility) *errs.Error {
	if !visibility.IsValid() {
		return errs.BadRequestError().AppendDetails("无效的可见性设置")
	}
	return nil
}

func ValidateSignature(signature string) *errs.Error {
	if utf8.RuneCountInString(signature) > 128 {
		return errs.BadRequestError().AppendDetails("无效的个性签名")
	}
	return nil
}

func ValidateBio(bio string) *errs.Error {
	if utf8.RuneCountInString(bio) > 2048 {
		return errs.BadRequestError().AppendDetails("无效的个人简介")
	}
	return nil
}

func ValidateBanReason(reason string) *errs.Error {
	if strings.TrimSpace(reason) == "" || utf8.RuneCountInString(reason) > 256 {
		return errs.BadRequestError().AppendDetails("无效的封禁原因")
	}
	return nil
}

func ValidateTOTPCode(code string) *errs.Error {
	if ok, err := regexTOTPCode.MatchString(code); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to validate totp code").AppendDetails("TOTP 验证码校验失败")
	} else if !ok {
		return errs.BadRequestError().AppendDetails("无效的 TOTP 验证码")
	}
	return nil
}

func ValidatePermissionValue(value string) *errs.Error {
	if value == "" {
		return errs.BadRequestError().AppendDetails("权限值为空")
	}
	if utf8.RuneCountInString(value) > 96 {
		return errs.BadRequestError().AppendDetails("权限值过长")
	}
	return nil
}

func ValidatePermissionDescription(description string) *errs.Error {
	if utf8.RuneCountInString(description) > 256 {
		return errs.BadRequestError().AppendDetails("权限描述过长")
	}
	return nil
}

func ValidateUserGroupName(name string) *errs.Error {
	if name == "" {
		return errs.BadRequestError().AppendDetails("用户组名为空")
	}
	if utf8.RuneCountInString(name) > 128 {
		return errs.BadRequestError().AppendDetails("用户组名过长")
	}
	return nil
}

func ValidateUserGroupNote(note string) *errs.Error {
	if utf8.RuneCountInString(note) > 256 {
		return errs.BadRequestError().AppendDetails("用户组备注过长")
	}
	return nil
}

func ValidateGrantPermission(permission string) *errs.Error {
	if permission == "" {
		return errs.BadRequestError().AppendDetails("权限名为空")
	}
	if _, err := perm.ParsePermission(permission); err != nil {
		return errs.BadRequestError().AppendDetails("无效的权限名")
	}
	if utf8.RuneCountInString(permission) > 128 {
		return errs.BadRequestError().AppendDetails("权限名过长")
	}
	return nil
}

func ValidateGrantNote(note string) *errs.Error {
	if utf8.RuneCountInString(note) > 256 {
		return errs.BadRequestError().AppendDetails("备注过长")
	}
	return nil
}

func ValidateValidRange(validFrom, validUntil *time.Time) *errs.Error {
	if validFrom != nil && validUntil != nil && !validUntil.After(*validFrom) {
		return errs.BadRequestError().AppendDetails("有效期无效")
	}
	return nil
}
