package filestore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fdfz-student-id/internal/cfg"
)

func TestUploadExistingFile(t *testing.T) {
	var got StoreFileReq
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/internal/upload/store" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer token")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	oldCfg := cfg.C
	cfg.C = &cfg.Config{
		FilestoreInternalEndpoint: server.URL,
		FilestoreHMACSecret:       "test-secret",
	}
	defer func() { cfg.C = oldCfg }()

	err := UploadExistingFile("uploads/migration/1.png", &StoreFileReq{
		Slug:         "/student_id/proof_images/test",
		FileName:     "test.png",
		ShouldUpsert: true,
		ShouldCopy:   true,
	})
	if err != nil {
		t.Fatalf("UploadExistingFile() error = %+v", err)
	}

	if got.FilePath != "uploads/migration/1.png" {
		t.Errorf("file_path = %q", got.FilePath)
	}
	if got.Slug != "/student_id/proof_images/test" {
		t.Errorf("slug = %q", got.Slug)
	}
	if got.FileName != "test.png" {
		t.Errorf("file_name = %q", got.FileName)
	}
	if !got.ShouldUpsert || !got.ShouldCopy {
		t.Errorf("should_upsert=%v should_copy=%v", got.ShouldUpsert, got.ShouldCopy)
	}
	if got.SHA512.Valid {
		t.Errorf("sha512 should be empty for filestore-side calculation")
	}
}
