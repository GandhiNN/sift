package report

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"strings"

	"sift/audit"
)

//go:embed template.html
var templateFS embed.FS

func findingsToCSVBase64(findings []audit.Finding) string {
	var sb strings.Builder
	sb.WriteString("Profile,Service,Check,ResourceID,RiskLevel,Detail,Remediation\n")
	for _, f := range findings {
		detail := strings.ReplaceAll(f.Detail, "\"", "\"\"")
		remediation := ""
		if f.Remediation != nil {
			remediation = strings.ReplaceAll(f.Remediation.Action, "\"", "\"\"")
		}
		sb.WriteString(
			fmt.Sprintf(
				"%s,%s,%s,%s,%s,\"%s\",\"%s\"\n",
				f.Profile,
				f.Service,
				f.Check,
				f.ResourceID,
				f.RiskLevel,
				detail,
				remediation,
			),
		)
	}
	return base64.StdEncoding.EncodeToString([]byte(sb.String()))
}

var funcMap = template.FuncMap{
	"inc":       func(i int) int { return i + 1 },
	"lower":     strings.ToLower,
	"join":      strings.Join,
	"money":     fmtCost,
	"csvBase64": findingsToCSVBase64,
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
