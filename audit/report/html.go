package report

import (
	"embed"
	"html/template"
	"io"
	"strings"
)

//go:embed template.html
var templateFS embed.FS

var funcMap = template.FuncMap{
	"inc":   func(i int) int { return i + 1 },
	"lower": strings.ToLower,
	"join":  strings.Join,
	"pct": func(a, b float64) float64 {
		if b == 0 {
			return 0
		}
		return a / b * 100
	},
	"sub":     func(a, b float64) float64 { return a - b },
	"toFloat": func(i int) float64 { return float64(i) },
}

func RenderHTML(w io.Writer, r *ReportData) error {
	tmpl, err := template.New("template.html").Funcs(funcMap).ParseFS(templateFS, "template.html")
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r)
}
