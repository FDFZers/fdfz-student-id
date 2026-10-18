package validation

import (
	"fdfz-student-id/internal/errs"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/dlclark/regexp2"
)

var regexUsername = regexp2.MustCompile(`\A[a-zA-Z0-9_-]{4,32}\z`, regexp2.None)
var regexNickname = regexp2.MustCompile(`\A.{1,32}\z`, regexp2.None)
var regexRealName = regexp2.MustCompile(`\A[\u4e00-\u9fff\u00b7]{1,4}\z`, regexp2.None)
var regexStudentNum = regexp2.MustCompile(`\A\d{8}\z`, regexp2.None)
var regexEmail = regexp2.MustCompile(`\A([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"(\[\]!#-[^-~ \t]|(\\[\t -~]))+\")@([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\[[\t -Z^-~]*])\z`, regexp2.None)
var regexPassword = regexp2.MustCompile(`\A(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}\z`, regexp2.None)
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
