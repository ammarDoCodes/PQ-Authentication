package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var dashboardFiles embed.FS

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	content, err := dashboardFiles.ReadFile("static/dashboard.html")
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "DASHBOARD_UNAVAILABLE", "Dashboard unavailable", "The dashboard could not be loaded.", false)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) dashboardAsset(w http.ResponseWriter, r *http.Request) {
	name := ""
	switch r.URL.Path {
	case "/dashboard.js":
		name = "dashboard.js"
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case "/dashboard.css":
		name = "dashboard.css"
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		s.notFound(w, r)
		return
	}
	content, err := fs.ReadFile(dashboardFiles, "static/"+name)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "DASHBOARD_UNAVAILABLE", "Dashboard unavailable", "The dashboard could not be loaded.", false)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
