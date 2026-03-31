package pages

import (
	"html/template"
	"io/fs"

	"github.com/gin-gonic/gin"
)

type PagesHandler struct {
	templates *template.Template
	staticFS  fs.FS
}

func NewPagesHandler() *PagesHandler {
	return &PagesHandler{
		templates: parseTemplates(),
		staticFS:  staticSubFS(),
	}
}

func (h *PagesHandler) StaticFS() fs.FS {
	return h.staticFS
}

func (h *PagesHandler) LoginPage(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	h.templates.ExecuteTemplate(c.Writer, "login", nil)
}

func (h *PagesHandler) SignupPage(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	h.templates.ExecuteTemplate(c.Writer, "signup", nil)
}

func (h *PagesHandler) DashboardPage(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	h.templates.ExecuteTemplate(c.Writer, "dashboard", nil)
}
