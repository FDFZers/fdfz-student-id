package handling

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"io"
	"mime/multipart"
	"net/http"
)

// DetectMIMEType 读取文件头前 512 字节检测 MIME 类型并校验白名单。
// 检测会消耗上传文件的读取偏移，调用后不可复用。
func DetectMIMEType(fileHeader *multipart.FileHeader, allowedTypes map[string]struct{}) (string, *errs.Error) {
	file, err := fileHeader.Open()
	if err != nil {
		return "", errs.CreateAndLogInternalError(err, "Failed to open file while detecting mime").AppendDetails("文件类型检测失败")
	}
	defer func() {
		_ = file.Close()
	}()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errs.CreateAndLogInternalError(err, "Failed to read file while detecting mime").AppendDetails("文件类型检测失败")
	}
	if n == 0 {
		return "", errs.BadRequestError().AppendDetails("文件为空")
	}

	fileType := http.DetectContentType(buffer[:n])
	if _, ok := allowedTypes[fileType]; !ok {
		return "", errs.UnsupportedMediaTypeError().AppendDetails("文件类型不受支持")
	}
	return fileType, nil
}

// ImageExtension 根据检测到的图片 MIME 返回固定扩展名，未知图片类型返回空串。
// 上传接口应使用该扩展名而非客户端文件名后缀，避免类型混淆。
func ImageExtension(mimeType string) string {
	switch mimeType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
}
