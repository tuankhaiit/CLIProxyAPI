package management

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// GetAntigravityQuotas retrieves the model quotas for Antigravity accounts.
func (h *Handler) GetAntigravityQuotas(c *gin.Context) {
	requestedID := c.Query("id")

	// Filter accounts
	var targets []*coreauth.Auth
	allAuths, errList := h.tokenStore.List(c.Request.Context())
	if errList != nil {
		log.Errorf("failed to list auths: %v", errList)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list auths"})
		return
	}
	for _, auth := range allAuths {
		if auth.Provider != "antigravity" {
			continue
		}
		if requestedID != "" && auth.ID != requestedID && auth.FileName != requestedID {
			continue
		}
		targets = append(targets, auth)
	}

	if len(targets) == 0 {
		c.JSON(http.StatusOK, gin.H{"accounts": []any{}})
		return
	}

	type AccountResponse struct {
		ID        string                               `json:"id"`
		Email     string                               `json:"email"`
		ProjectID string                               `json:"project_id"`
		Models    []executor.AntigravityModelWithQuota `json:"models,omitempty"`
		Error     string                               `json:"error,omitempty"`
	}

	responses := make([]AccountResponse, len(targets))

	g, ctx := errgroup.WithContext(c.Request.Context())
	// Limit concurrency
	g.SetLimit(5)

	for i, auth := range targets {
		idx := i
		targetAuth := auth
		g.Go(func() error {
			resp := AccountResponse{
				ID:    targetAuth.ID,
				Email: getStringMeta(targetAuth.Metadata, "email"),
			}

			// 1. Resolve Project ID
			projectID := getStringMeta(targetAuth.Metadata, "project_id")

			// Helper to refresh token if needed
			exec := executor.NewAntigravityExecutor(h.cfg)

			// If project ID is missing, we try to fetch it first.
			if projectID == "" {
				// Ensure we have a valid token first
				updatedAuth, errRefresh := exec.Refresh(ctx, targetAuth)
				if errRefresh == nil && updatedAuth != nil {
					targetAuth = updatedAuth
				}

				accessToken := getStringMeta(targetAuth.Metadata, "access_token")
				if accessToken != "" {
					httpClient := util.SetProxy(&h.cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second})
					pid, errProj := sdkAuth.FetchAntigravityProjectID(ctx, accessToken, httpClient)
					if errProj == nil && pid != "" {
						projectID = pid
						// Update metadata and persist
						if targetAuth.Metadata == nil {
							targetAuth.Metadata = make(map[string]any)
						}
						targetAuth.Metadata["project_id"] = pid
						if _, errSave := h.tokenStore.Save(ctx, targetAuth); errSave != nil {
							log.Warnf("failed to save updated project ID for %s: %v", targetAuth.ID, errSave)
						}
					} else {
						log.Warnf("failed to fetch project ID for %s: %v", targetAuth.ID, errProj)
					}
				}
			}
			resp.ProjectID = projectID

			// 2. Fetch Models & Quota
			// The executor's FetchAntigravityModelsWithQuota handles token refresh internally as well,
			// but we pass our potentially updated auth (in memory) to it.
			models, err := executor.FetchAntigravityModelsWithQuota(ctx, targetAuth, h.cfg, projectID)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Models = models
			}

			responses[idx] = resp
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		log.Errorf("errgroup error in GetAntigravityQuotas: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"accounts": responses})
}

func getStringMeta(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
