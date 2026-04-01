package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authModel "github.com/lin-snow/ech0/internal/model/auth"
	commonModel "github.com/lin-snow/ech0/internal/model/common"
	"github.com/lin-snow/ech0/pkg/viewer"
)

func TestRequireScopes_ReturnsScopeForbiddenCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeAccess,
				[]string{authModel.ScopeEchoRead},
				[]string{authModel.AudiencePublic},
				"jti-scope-test",
			),
		)
		c.Next()
	})
	r.GET("/protected", RequireScopes(authModel.ScopeAdminSettings), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if got := parseErrorCode(rec.Body.Bytes()); got != commonModel.ErrCodeScopeForbidden {
		t.Fatalf("expected error code %s, got %s", commonModel.ErrCodeScopeForbidden, got)
	}
}

func TestRequireScopes_ReturnsAudienceForbiddenCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeAccess,
				[]string{authModel.ScopeAdminSettings},
				[]string{"unknown-audience"},
				"jti-audience-test",
			),
		)
		c.Next()
	})
	r.GET("/protected", RequireScopes(authModel.ScopeAdminSettings), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if got := parseErrorCode(rec.Body.Bytes()); got != commonModel.ErrCodeAudienceForbidden {
		t.Fatalf("expected error code %s, got %s", commonModel.ErrCodeAudienceForbidden, got)
	}
}

func TestRequireAccessTokenScopes_RejectsSessionToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeSession,
				nil,
				nil,
				"",
			),
		)
		c.Next()
	})
	r.POST("/protected", RequireAccessTokenScopes(authModel.ScopeCommentWrite), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if got := parseErrorCode(rec.Body.Bytes()); got != commonModel.ErrCodeTokenInvalid {
		t.Fatalf("expected error code %s, got %s", commonModel.ErrCodeTokenInvalid, got)
	}
}

func TestRequireAccessTokenScopes_AllowsScopedAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeAccess,
				[]string{authModel.ScopeCommentWrite},
				[]string{authModel.AudienceIntegration},
				"jti-comment-write",
			),
		)
		c.Next()
	})
	r.POST("/protected", RequireAccessTokenScopes(authModel.ScopeCommentWrite), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireAccessTokenAudienceScopes_RejectsWrongAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeAccess,
				[]string{authModel.ScopeCommentWrite},
				[]string{authModel.AudiencePublic},
				"jti-comment-write-public",
			),
		)
		c.Next()
	})
	r.POST(
		"/protected",
		RequireAccessTokenAudienceScopes(authModel.AudienceIntegration, authModel.ScopeCommentWrite),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if got := parseErrorCode(rec.Body.Bytes()); got != commonModel.ErrCodeAudienceForbidden {
		t.Fatalf("expected error code %s, got %s", commonModel.ErrCodeAudienceForbidden, got)
	}
}

func TestRequireAccessTokenAudienceScopes_AllowsMatchingAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		viewer.AttachToRequest(
			&c.Request,
			viewer.NewUserViewerWithToken(
				"user-1",
				authModel.TokenTypeAccess,
				[]string{authModel.ScopeCommentWrite},
				[]string{authModel.AudienceIntegration},
				"jti-comment-write-integration",
			),
		)
		c.Next()
	})
	r.POST(
		"/protected",
		RequireAccessTokenAudienceScopes(authModel.AudienceIntegration, authModel.ScopeCommentWrite),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func parseErrorCode(body []byte) string {
	var payload struct {
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(body, &payload)
	return payload.ErrorCode
}
