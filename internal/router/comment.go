package router

import (
	"github.com/gin-gonic/gin"
	"github.com/lin-snow/ech0/internal/captcha"
	"github.com/lin-snow/ech0/internal/handler"
	"github.com/lin-snow/ech0/internal/middleware"
	authModel "github.com/lin-snow/ech0/internal/model/auth"
)

func setupCommentRoutes(appRouterGroup *AppRouterGroup, h *handler.Bundle) {
	captchaHandler, err := captcha.NewHTTPHandler("/api")
	if err != nil {
		panic(err)
	}

	// Public
	appRouterGroup.PublicRouterGroup.Any("/cap/*any", gin.WrapH(captchaHandler))
	appRouterGroup.PublicRouterGroup.GET("/comments/form", middleware.NoCache(), h.CommentHandler.GetFormMeta())
	appRouterGroup.PublicRouterGroup.GET("/comments", middleware.NoCache(), h.CommentHandler.ListCommentsByEchoID())
	appRouterGroup.PublicRouterGroup.GET(
		"/comments/public",
		middleware.NoCache(),
		h.CommentHandler.ListPublicComments(),
	)
	appRouterGroup.PublicRouterGroup.POST("/comments", h.CommentHandler.CreateComment())
	appRouterGroup.AuthRouterGroup.POST(
		"/comments/integration",
		middleware.RequireAccessTokenAudienceScopes(
			authModel.AudienceIntegration,
			authModel.ScopeCommentWrite,
		),
		h.CommentHandler.CreateIntegrationComment(),
	)

	// Admin Panel
	appRouterGroup.AuthRouterGroup.GET(
		"/panel/comments",
		middleware.RequireScopes(authModel.ScopeCommentRead),
		h.CommentHandler.ListPanelComments(),
	)
	appRouterGroup.AuthRouterGroup.GET(
		"/panel/comments/:id",
		middleware.RequireScopes(authModel.ScopeCommentRead),
		h.CommentHandler.GetCommentByID(),
	)
	appRouterGroup.AuthRouterGroup.PATCH(
		"/panel/comments/:id/status",
		middleware.RequireScopes(authModel.ScopeCommentMod),
		h.CommentHandler.UpdateCommentStatus(),
	)
	appRouterGroup.AuthRouterGroup.PATCH(
		"/panel/comments/:id/hot",
		middleware.RequireScopes(authModel.ScopeCommentMod),
		h.CommentHandler.UpdateCommentHot(),
	)
	appRouterGroup.AuthRouterGroup.DELETE(
		"/panel/comments/:id",
		middleware.RequireScopes(authModel.ScopeCommentMod),
		h.CommentHandler.DeleteComment(),
	)
	appRouterGroup.AuthRouterGroup.POST(
		"/panel/comments/batch",
		middleware.RequireScopes(authModel.ScopeCommentMod),
		h.CommentHandler.BatchAction(),
	)
	appRouterGroup.AuthRouterGroup.GET(
		"/panel/comments/settings",
		middleware.RequireScopes(authModel.ScopeAdminSettings),
		h.CommentHandler.GetCommentSetting(),
	)
	appRouterGroup.AuthRouterGroup.PUT(
		"/panel/comments/settings",
		middleware.RequireScopes(authModel.ScopeAdminSettings),
		h.CommentHandler.UpdateCommentSetting(),
	)
	appRouterGroup.AuthRouterGroup.POST(
		"/panel/comments/settings/test-email",
		middleware.RequireScopes(authModel.ScopeAdminSettings),
		h.CommentHandler.TestCommentEmail(),
	)
}
