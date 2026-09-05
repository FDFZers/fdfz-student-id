package errs

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
	"github.com/lib/pq"
)

type ErrorInfo struct {
	Error string            `json:"error"`
	Data  null.Value[gin.H] `json:"data"`
}

type Error struct {
	HTTPCode int
	Info     ErrorInfo
}

var InternalError = CreateError(http.StatusInternalServerError, "internal_error")
var BadRequestError = CreateError(http.StatusBadRequest, "bad_request")
var IllegalStateError = CreateError(http.StatusUnprocessableEntity, "illegal_state")
var AuthFailedError = CreateError(http.StatusUnauthorized, "auth_failed")

func CreateError(httpCode int, id string) *Error {
	return &Error{
		HTTPCode: httpCode,
		Info: ErrorInfo{
			Error: id,
		},
	}
}

func CreateErrorWithData(httpCode int, id string, data gin.H) *Error {
	return &Error{
		HTTPCode: httpCode,
		Info: ErrorInfo{
			Error: id,
			Data:  null.ValueFrom(data),
		},
	}
}

func (e *Error) Respond(c *gin.Context) {
	c.JSON(e.HTTPCode, e.Info)
}

func CreateInvalidFieldError(field string) *Error {
	return CreateErrorWithData(http.StatusBadRequest, "invalid_field", gin.H{"item": field})
}

func CreateNotFoundError(item string) *Error {
	return CreateErrorWithData(http.StatusNotFound, "not_found", gin.H{"item": item})
}

func CreateFieldConflictError(field, item string) *Error {
	return CreateErrorWithData(http.StatusConflict, "conflict", gin.H{"field": item, "item": item})
}

func CreateAndLogInternalError[T any](err T, msg string, args ...any) *Error {
	slog.Error(msg, append([]any{"error", err}, args...)...)
	return InternalError
}

func CreatePGError(err error, msg string, item string) *Error {
	if errors.Is(err, sql.ErrNoRows) {
		return CreateNotFoundError(item)
	}

	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || !strings.HasPrefix(string(pgErr.Code), "23") {
		return CreateAndLogInternalError(err, msg)
	}

	return CreateFieldConflictError(pgErr.Constraint, item)
}
