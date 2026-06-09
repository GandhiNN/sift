package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

func Output(format string, data any) error {
	return OutputWithFilter(format, data, "", "", time.Time{}, "")
}

func OutputWithFilter(
	format string,
	data any,
	minRisk string,
	sortBy string,
	startTime time.Time,
	outputFile string,
) error {
	if minRisk != "" {
		data = filterByRisk(data, minRisk)
	}

	findings, _ := data.([]Finding)
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return nil
	}

	if sortBy == "cost" {
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].EstimatedMonthlyCost > findings[j].EstimatedMonthlyCost
		})
		data = findings
	}

	out := os.Stdout
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "json":
		b, err := json.MarshalIndent(data, "", "	")
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(b))
	case "csv":
		if err := writeCSV(data, out); err != nil {
			return err
		}
	case "table":
		writeTable(data, out)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
	printSummary(data, startTime)
	return nil
}

var riskOrder = map[string]int{
	"MINIMAL":  0,
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

var riskColor = map[string]string{
	"CRITICAL": "\033[1;31m", // bold red
	"HIGH":     "\033[31m",   // red
	"MEDIUM":   "\033[33m",   // yellow
	"LOW":      "\033[36m",   // cyan
	"MINIMAL":  "\033[32m",   // green
}

const colorReset = "\033[0m"

func colorRisk(risk string) string {
	if c, ok := riskColor[risk]; ok {
		return c + risk + colorReset
	}
	return risk
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func writeTable(data any, out io.Writer) {
	findings, ok := data.([]Finding)
	if !ok || len(findings) == 0 {
		return
	}

	// Sort by risk descending
	sort.Slice(findings, func(i, j int) bool {
		return riskOrder[findings[i].RiskLevel] > riskOrder[findings[j].RiskLevel]
	})

	hasRegion := false
	hasCost := false
	for _, f := range findings {
		if f.Region != "" {
			hasRegion = true
		}
		if f.EstimatedMonthlyCost > 0 {
			hasCost = true
		}
	}

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	if hasRegion {
		if hasCost {
			fmt.Fprintln(w, "RISK\tREGION\tSERVICE\tRESOURCE\tCHECK\t$/MO\tDETAIL")
			for _, f := range findings {
				cost := ""
				if f.EstimatedMonthlyCost > 0 {
					cost = fmt.Sprintf("$%.2f", f.EstimatedMonthlyCost)
				}
				fmt.Fprintf(
					w,
					"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					colorRisk(
						f.RiskLevel,
					),
					f.Region,
					f.Service,
					f.ResourceID,
					f.Check,
					cost,
					truncate(f.Detail, 80),
				)
			}
		} else {
			fmt.Fprintln(w, "RISK\tREGION\tSERVICE\tRESOURCE\tCHECK\tDETAIL")
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					colorRisk(f.RiskLevel), f.Region, f.Service, f.ResourceID, f.Check, truncate(f.Detail, 80),
				)
			}
		}
	} else {
		if hasCost {
			fmt.Fprintln(w, "RISK\tSERVICE\tRESOURCE\tCHECK\t$/MO\tDETAIL")
			for _, f := range findings {
				cost := ""
				if f.EstimatedMonthlyCost > 0 {
					cost = fmt.Sprintf("$%.2f", f.EstimatedMonthlyCost)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					colorRisk(f.RiskLevel), f.Service, f.ResourceID, f.Check, cost, truncate(f.Detail, 80),
				)
			}
		} else {
			fmt.Fprintln(w, "RISK\tSERVICE\tRESOURCE\tCHECK\tDETAIL")
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					colorRisk(f.RiskLevel), f.Service, f.ResourceID, f.Check, truncate(f.Detail, 80),
				)
			}
		}
	}
	w.Flush()
}

func filterByRisk(data any, minRisk string) any {
	minLevel := riskOrder[strings.ToUpper(minRisk)]

	if findings, ok := data.([]Finding); ok {
		var filtered []Finding
		for _, f := range findings {
			if riskOrder[f.RiskLevel] >= minLevel {
				filtered = append(filtered, f)
			}
		}
		return filtered
	}
	return data
}

func writeCSV(data any, out io.Writer) error {
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		// single item - wrap in slice
		v = reflect.ValueOf([]any{data})
	}
	if v.Kind() != reflect.Slice || v.Len() == 0 {
		return nil
	}

	w := csv.NewWriter(out)
	defer w.Flush()

	// headers from json tags
	elem := v.Index(0)
	if elem.Kind() == reflect.Ptr {
		elem = elem.Elem()
	}
	if elem.Kind() == reflect.Interface {
		elem = elem.Elem()
	}
	t := elem.Type()
	headers := csvHeaders(t)
	w.Write(headers)

	// rows
	for i := 0; i < v.Len(); i++ {
		row := csvRow(v.Index(i))
		w.Write(row)
	}
	return nil
}

func csvHeaders(t reflect.Type) []string {
	var headers []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			headers = append(headers, csvHeaders(f.Type)...)
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		headers = append(headers, name)
	}
	return headers
}

func csvRow(v reflect.Value) []string {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	var row []string
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			row = append(row, csvRow(v.Field(i))...)
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Ptr {
			if fv.IsNil() {
				row = append(row, "")
			} else {
				elem := fv.Elem()
				if elem.Kind() == reflect.Struct {
					var buf strings.Builder
					enc := json.NewEncoder(&buf)
					enc.SetEscapeHTML(false)
					enc.Encode(fv.Interface())
					row = append(row, strings.TrimSpace(buf.String()))
				} else {
					row = append(row, fmt.Sprintf("%v", elem))
				}
			}
		} else if fv.Kind() == reflect.Slice {
			parts := make([]string, fv.Len())
			for j := 0; j < fv.Len(); j++ {
				parts[j] = fmt.Sprintf("%v", fv.Index(j))
			}
			row = append(row, strings.Join(parts, ";"))
		} else if fv.Kind() == reflect.Map {
			parts := make([]string, 0, fv.Len())
			for _, k := range fv.MapKeys() {
				parts = append(parts, fmt.Sprintf("%s=%s", k, fv.MapIndex(k)))
			}
			sort.Strings(parts)
			row = append(row, strings.Join(parts, ";"))
		} else {
			row = append(row, fmt.Sprintf("%v", fv))
		}
	}
	return row
}

func printSummary(data any, startTime time.Time) {
	findings, ok := data.([]Finding)
	if !ok || len(findings) == 0 {
		return
	}

	counts := map[string]int{}
	var totalWaste float64
	for _, f := range findings {
		counts[f.RiskLevel]++
		if f.Status != "PASS" && f.EstimatedMonthlyCost > 0 {
			totalWaste += f.EstimatedMonthlyCost
		}
	}
	summary := struct {
		Summary struct {
			Total                 int     `json:"total"`
			Critical              int     `json:"critical"`
			High                  int     `json:"high"`
			Medium                int     `json:"medium"`
			Low                   int     `json:"low"`
			Minimal               int     `json:"minimal"`
			EstimatedWasteMonthly float64 `json:"estimated_waste_monthly"`
			DurationSeconds       float64 `json:"duration_seconds"`
		} `json:"summary"`
	}{}
	summary.Summary.Total = len(findings)
	summary.Summary.Critical = counts["CRITICAL"]
	summary.Summary.High = counts["HIGH"]
	summary.Summary.Medium = counts["MEDIUM"]
	summary.Summary.Low = counts["LOW"]
	summary.Summary.Minimal = counts["MINIMAL"]
	summary.Summary.EstimatedWasteMonthly = totalWaste
	if !startTime.IsZero() {
		summary.Summary.DurationSeconds = time.Since(startTime).Seconds()
	}

	b, _ := json.Marshal(summary)
	fmt.Fprintln(os.Stderr, "\n", string(b))
}

// Returns true if any findings are CRITICAL or HIGH
func HasHighRiskFindings(data any) bool {
	findings, ok := data.([]Finding)
	if !ok {
		return false
	}
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			return true
		}
	}
	return false
}

func OutputResources(
	format string,
	resources []Resource,
	startTime time.Time,
	outputFile string,
) error {
	if len(resources) == 0 {
		fmt.Println("No resources found.")
		return nil
	}

	out := os.Stdout
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "json":
		b, err := json.MarshalIndent(resources, "", "\t")
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(b))
	case "csv":
		if err := writeResourceCSV(resources, out); err != nil {
			return err
		}
	case "table":
		writeResourceTable(resources, out)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	if !startTime.IsZero() {
		fmt.Fprintf(
			os.Stderr,
			"{\"total\":%d,\"duration_seconds\":%.1f}\n",
			len(resources),
			time.Since(startTime).Seconds(),
		)
	}
	return nil
}

// resourceColumns defines per-type column layouts for list output.
// Each entry maps property keys to display headers.
var resourceColumns = map[string][]struct{ Key, Header string }{
	"glue/job": {
		{"command", "CMD"},
		{"workers", "WORKERS"},
		{"runs_last_30", "RUNS(30)"},
		{"avg_dpu_hours", "AVG DPU-HR"},
		{"last_run_time", "LAST RUN"},
		{"last_run_status", "STATUS"},
	},
	"vpc/subnet": {
		{"vpc_id", "VPC"},
		{"az", "AZ"},
		{"cidr", "CIDR"},
		{"available_ips", "AVAILABLE"},
		{"total_ips", "TOTAL"},
		{"usage_pct", "USAGE%"},
		{"name", "NAME"},
	},
}

func writeResourceTable(resources []Resource, out io.Writer) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	// Determine layout from first resource
	key := ""
	if len(resources) > 0 {
		key = resources[0].Service + "/" + resources[0].Type
	}

	if cols, ok := resourceColumns[key]; ok {
		// Typed columns
		header := "RESOURCE"
		for _, c := range cols {
			header += "\t" + c.Header
		}
		header += "\tTAGS"
		fmt.Fprintln(w, header)
		for _, r := range resources {
			line := r.ResourceID
			for _, c := range cols {
				line += "\t" + r.Properties[c.Key]
			}
			line += "\t" + truncate(formatMap(r.Tags), 40)
			fmt.Fprintln(w, line)
		}
	} else {
		// Fallback generic
		fmt.Fprintln(w, "SERVICE\tRESOURCE\tTYPE\tTAGS\tPROPERTIES")
		for _, r := range resources {
			tags := formatMap(r.Tags)
			props := formatMap(r.Properties)
			fmt.Fprintf(
				w,
				"%s\t%s\t%s\t%s\t%s\n",
				r.Service,
				r.ResourceID,
				r.Type,
				truncate(tags, 40),
				truncate(props, 80),
			)
		}
	}
	w.Flush()
}

func writeResourceCSV(resources []Resource, out io.Writer) error {
	w := csv.NewWriter(out)
	defer w.Flush()
	key := ""
	if len(resources) > 0 {
		key = resources[0].Service + "/" + resources[0].Type
	}

	if cols, ok := resourceColumns[key]; ok {
		header := []string{"resource_id"}
		for _, c := range cols {
			header = append(header, c.Key)
		}
		w.Write(header)
		for _, r := range resources {
			row := []string{r.ResourceID}
			for _, c := range cols {
				row = append(row, r.Properties[c.Key])
			}
			w.Write(row)
		}
	} else {
		w.Write([]string{"region", "service", "resource_id", "type", "tags", "properties"})
		for _, r := range resources {
			w.Write([]string{
				r.Region, r.Service, r.ResourceID, r.Type,
				formatMap(r.Tags), formatMap(r.Properties),
			})
		}
	}
	return nil
}

func formatMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
