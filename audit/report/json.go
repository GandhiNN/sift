package report

import (
	"encoding/json"
	"io"
)

func RenderJSON(w io.Writer, r *ReportData) {
	b, _ := json.MarshalIndent(r, "", "  ")
	w.Write(b)
	w.Write([]byte("\n"))
}
