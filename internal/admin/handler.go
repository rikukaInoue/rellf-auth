package admin

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
)

type AdminHandler struct {
	auth      cognito.AdminService
	loginAuth cognito.Service
	cfg       *config.Config
	templates *template.Template
	staticFS  fs.FS
}

func NewAdminHandler(auth cognito.AdminService, loginAuth cognito.Service, cfg *config.Config) *AdminHandler {
	return &AdminHandler{
		auth:      auth,
		loginAuth: loginAuth,
		cfg:       cfg,
		templates: parseTemplates(),
		staticFS:  staticSubFS(),
	}
}

func (h *AdminHandler) StaticFS() fs.FS {
	return h.staticFS
}

// --- Login / Logout ---

func (h *AdminHandler) LoginPage(c *gin.Context) {
	h.templates.ExecuteTemplate(c.Writer, "login", gin.H{"Error": ""})
}

func (h *AdminHandler) LoginSubmit(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	tokens, err := h.loginAuth.Login(c.Request.Context(), email, password)
	if err != nil {
		h.templates.ExecuteTemplate(c.Writer, "login", gin.H{"Error": "Invalid email or password"})
		return
	}

	c.SetCookie("admin_token", tokens.IDToken, 3600, "/admin", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/users")
}

func (h *AdminHandler) Logout(c *gin.Context) {
	c.SetCookie("admin_token", "", -1, "/admin", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// --- Users ---

func (h *AdminHandler) ListUsers(c *gin.Context) {
	search := c.Query("search")
	nextToken := c.Query("next")

	filter := ""
	if search != "" {
		filter = `email ^= "` + search + `"`
	}

	var paginationToken *string
	if nextToken != "" {
		paginationToken = &nextToken
	}

	result, err := h.auth.AdminListUsers(c.Request.Context(), filter, 20, paginationToken)
	if err != nil {
		h.renderError(c, "Failed to list users: "+err.Error())
		return
	}

	var nextTokenStr string
	if result.PaginationToken != nil {
		nextTokenStr = *result.PaginationToken
	}

	h.render(c, "layout", gin.H{
		"Users":     result.Users,
		"Search":    search,
		"NextToken": nextTokenStr,
	})
}

func (h *AdminHandler) UserDetail(c *gin.Context) {
	username := c.Param("username")

	user, err := h.auth.AdminGetUser(c.Request.Context(), username)
	if err != nil {
		h.setFlash(c, "error", "User not found: "+err.Error())
		c.Redirect(http.StatusSeeOther, "/admin/users")
		return
	}

	h.render(c, "layout", gin.H{
		"User": user,
	})
}

func (h *AdminHandler) CreateUserPage(c *gin.Context) {
	h.render(c, "layout", nil)
}

func (h *AdminHandler) CreateUserSubmit(c *gin.Context) {
	email := c.PostForm("email")
	tempPassword := c.PostForm("temp_password")

	user, err := h.auth.AdminCreateUser(c.Request.Context(), email, tempPassword)
	if err != nil {
		h.setFlash(c, "error", "Failed to create user: "+err.Error())
		c.Redirect(http.StatusSeeOther, "/admin/users/new")
		return
	}

	h.setFlash(c, "success", "User created: "+user.Email)
	c.Redirect(http.StatusSeeOther, "/admin/users/"+user.Username)
}

func (h *AdminHandler) ConfirmUser(c *gin.Context) {
	username := c.Param("username")
	if err := h.auth.AdminConfirmSignUp(c.Request.Context(), username); err != nil {
		h.setFlash(c, "error", "Failed to confirm user: "+err.Error())
	} else {
		h.setFlash(c, "success", "User confirmed")
	}
	c.Redirect(http.StatusSeeOther, "/admin/users/"+username)
}

func (h *AdminHandler) ResetPassword(c *gin.Context) {
	username := c.Param("username")
	if err := h.auth.AdminResetPassword(c.Request.Context(), username); err != nil {
		h.setFlash(c, "error", "Failed to reset password: "+err.Error())
	} else {
		h.setFlash(c, "success", "Password reset initiated")
	}
	c.Redirect(http.StatusSeeOther, "/admin/users/"+username)
}

func (h *AdminHandler) DisableUser(c *gin.Context) {
	username := c.Param("username")
	if err := h.auth.AdminDisableUser(c.Request.Context(), username); err != nil {
		h.setFlash(c, "error", "Failed to disable user: "+err.Error())
	} else {
		h.setFlash(c, "success", "User disabled")
	}
	c.Redirect(http.StatusSeeOther, "/admin/users/"+username)
}

func (h *AdminHandler) EnableUser(c *gin.Context) {
	username := c.Param("username")
	if err := h.auth.AdminEnableUser(c.Request.Context(), username); err != nil {
		h.setFlash(c, "error", "Failed to enable user: "+err.Error())
	} else {
		h.setFlash(c, "success", "User enabled")
	}
	c.Redirect(http.StatusSeeOther, "/admin/users/"+username)
}

func (h *AdminHandler) DeleteUser(c *gin.Context) {
	username := c.Param("username")
	if err := h.auth.AdminDeleteUser(c.Request.Context(), username); err != nil {
		h.setFlash(c, "error", "Failed to delete user: "+err.Error())
	} else {
		h.setFlash(c, "success", "User deleted")
	}
	c.Redirect(http.StatusSeeOther, "/admin/users")
}

// --- helpers ---

func (h *AdminHandler) render(c *gin.Context, name string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}

	// Read and clear flash
	if flash, err := c.Cookie("flash_msg"); err == nil && flash != "" {
		data["Flash"] = flash
		if flashType, err := c.Cookie("flash_type"); err == nil {
			data["FlashType"] = flashType
		}
		c.SetCookie("flash_msg", "", -1, "/admin", "", false, false)
		c.SetCookie("flash_type", "", -1, "/admin", "", false, false)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	h.templates.ExecuteTemplate(c.Writer, name, data)
}

func (h *AdminHandler) renderError(c *gin.Context, msg string) {
	h.render(c, "layout", gin.H{
		"Flash":     msg,
		"FlashType": "error",
	})
}

func (h *AdminHandler) setFlash(c *gin.Context, flashType, msg string) {
	c.SetCookie("flash_msg", msg, 10, "/admin", "", false, false)
	c.SetCookie("flash_type", flashType, 10, "/admin", "", false, false)
}
