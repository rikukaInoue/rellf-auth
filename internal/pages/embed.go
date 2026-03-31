package pages

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func parseTemplates() *template.Template {
	return template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

func staticSubFS() fs.FS {
	sub, _ := fs.Sub(staticFS, "static")
	return sub
}
