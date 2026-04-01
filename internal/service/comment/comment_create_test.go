package service

import (
	"context"
	"errors"
	"testing"
	"time"

	authModel "github.com/lin-snow/ech0/internal/model/auth"
	model "github.com/lin-snow/ech0/internal/model/comment"
	userModel "github.com/lin-snow/ech0/internal/model/user"
	jwtUtil "github.com/lin-snow/ech0/internal/util/jwt"
	"github.com/lin-snow/ech0/pkg/viewer"
)

func TestCreateIntegrationComment_RespectsApprovalSetting(t *testing.T) {
	tests := []struct {
		name            string
		requireApproval bool
		wantStatus      model.Status
	}{
		{
			name:            "approval enabled keeps comment pending",
			requireApproval: true,
			wantStatus:      model.StatusPending,
		},
		{
			name:            "approval disabled auto approves comment",
			requireApproval: false,
			wantStatus:      model.StatusApproved,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubCommentRepository{}
			service := NewCommentService(
				nil,
				repo,
				stubCommentKeyValueRepository{
					raw: `{"enable_comment":true,"require_approval":` + boolString(tc.requireApproval) + `,"captcha_enabled":false}`,
				},
				nil,
				nil,
			)

			result, err := service.CreateIntegrationComment(
				context.Background(),
				"127.0.0.1",
				"test-agent",
				&model.CreateIntegrationCommentDto{
					EchoID:   "echo-1",
					Nickname: "Alice",
					Email:    "alice@example.com",
					Website:  "https://example.com",
					Content:  "hello from integration",
				},
			)
			if err != nil {
				t.Fatalf("create integration comment failed: %v", err)
			}
			if result.Status != tc.wantStatus {
				t.Fatalf("expected status %s, got %s", tc.wantStatus, result.Status)
			}
			if repo.created == nil {
				t.Fatal("expected comment to be created")
			}
			if repo.created.Source != model.SourceGuest {
				t.Fatalf("expected source %s, got %s", model.SourceGuest, repo.created.Source)
			}
			if repo.created.UserID != nil {
				t.Fatalf("expected integration comment user_id to be nil, got %v", *repo.created.UserID)
			}
		})
	}
}

func TestCanUsePrivilegedCommentIdentity_OnlySessionOrLegacyViewerAllowed(t *testing.T) {
	admin := userModel.User{ID: "admin-1", IsAdmin: true}

	if !canUsePrivilegedCommentIdentity(
		viewer.WithContext(context.Background(), viewer.NewUserViewerWithToken(
			admin.ID,
			authModel.TokenTypeSession,
			nil,
			nil,
			"",
		)),
		admin,
	) {
		t.Fatal("expected session viewer to retain privileged comment identity")
	}

	if canUsePrivilegedCommentIdentity(
		viewer.WithContext(context.Background(), viewer.NewUserViewerWithToken(
			admin.ID,
			authModel.TokenTypeAccess,
			[]string{authModel.ScopeCommentWrite},
			[]string{authModel.AudienceIntegration},
			"jti-integration",
		)),
		admin,
	) {
		t.Fatal("expected access token viewer to be treated as non-system comment")
	}

	if !canUsePrivilegedCommentIdentity(
		viewer.WithContext(context.Background(), viewer.NewUserViewer(admin.ID)),
		admin,
	) {
		t.Fatal("expected legacy viewer without token metadata to retain compatibility")
	}
}

func TestParseOptionalViewerFromAuthHeader_PreservesTokenMetadata(t *testing.T) {
	user := userModel.User{ID: "user-1", Username: "alice"}
	token, err := jwtUtil.GenerateToken(
		jwtUtil.CreateAccessClaimsWithExpiry(
			user,
			int64(time.Hour.Seconds()),
			[]string{authModel.ScopeCommentWrite},
			authModel.AudienceIntegration,
			"jti-comment-write",
		),
	)
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}

	v := ParseOptionalViewerFromAuthHeader("Bearer " + token)
	if v.UserID() != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, v.UserID())
	}
	if v.TokenType() != authModel.TokenTypeAccess {
		t.Fatalf("expected token type %s, got %s", authModel.TokenTypeAccess, v.TokenType())
	}
	if len(v.Scopes()) != 1 || v.Scopes()[0] != authModel.ScopeCommentWrite {
		t.Fatalf("expected comment:write scope, got %v", v.Scopes())
	}
	if len(v.Audience()) != 1 || v.Audience()[0] != authModel.AudienceIntegration {
		t.Fatalf("expected integration audience, got %v", v.Audience())
	}
	if v.TokenID() != "jti-comment-write" {
		t.Fatalf("expected token id jti-comment-write, got %s", v.TokenID())
	}
}

type stubCommentRepository struct {
	created *model.Comment
}

func (r *stubCommentRepository) CreateComment(_ context.Context, c *model.Comment) error {
	clone := *c
	if clone.ID == "" {
		clone.ID = "comment-1"
		c.ID = clone.ID
	}
	r.created = &clone
	return nil
}

func (r *stubCommentRepository) ListPublicByEchoID(context.Context, string) ([]model.Comment, error) {
	return nil, nil
}

func (r *stubCommentRepository) ListPublicComments(context.Context, int) ([]model.Comment, error) {
	return nil, nil
}

func (r *stubCommentRepository) ListComments(context.Context, model.ListCommentQuery) (model.PageResult[model.Comment], error) {
	return model.PageResult[model.Comment]{}, nil
}

func (r *stubCommentRepository) GetCommentByID(context.Context, string) (model.Comment, error) {
	return model.Comment{}, nil
}

func (r *stubCommentRepository) UpdateCommentStatus(context.Context, string, model.Status) error {
	return nil
}

func (r *stubCommentRepository) UpdateCommentHot(context.Context, string, bool) error {
	return nil
}

func (r *stubCommentRepository) DeleteComment(context.Context, string) error {
	return nil
}

func (r *stubCommentRepository) BatchUpdateStatus(context.Context, []string, model.Status) error {
	return nil
}

func (r *stubCommentRepository) BatchDelete(context.Context, []string) error {
	return nil
}

func (r *stubCommentRepository) CountByIPWithin(context.Context, string, int64) (int64, error) {
	return 0, nil
}

func (r *stubCommentRepository) CountByEmailWithin(context.Context, string, int64) (int64, error) {
	return 0, nil
}

func (r *stubCommentRepository) CountByUserWithin(context.Context, string, int64) (int64, error) {
	return 0, nil
}

func (r *stubCommentRepository) ExistsRecentDuplicate(
	context.Context,
	string,
	string,
	string,
	string,
	string,
	int64,
) (bool, error) {
	return false, nil
}

type stubCommentKeyValueRepository struct {
	raw string
}

func (r stubCommentKeyValueRepository) GetKeyValue(_ context.Context, key string) (string, error) {
	if key != model.CommentSystemSettingKey {
		return "", errors.New("not found")
	}
	return r.raw, nil
}

func (r stubCommentKeyValueRepository) AddKeyValue(context.Context, string, string) error {
	return nil
}

func (r stubCommentKeyValueRepository) AddOrUpdateKeyValue(context.Context, string, string) error {
	return nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

var _ Repository = (*stubCommentRepository)(nil)
var _ KeyValueRepository = (*stubCommentKeyValueRepository)(nil)
