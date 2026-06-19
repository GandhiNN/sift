package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sift/audit/ai"
)

const reportPrompt = `You are an AWS infrastructure expert writing for business stakeholders.
Given the platform health data below, produce:
1. A 2-3 sentence executive summary (plain language, no jargon)
2. Exactly 3 prioritized recommended actions (one line each, most impactful first)

Format your response exactly as:
SUMMARY:
<your summary>

ACTIONS:
1. <action>
2. <action>
3. <action>`

func Enrich(r *ReportData) error {
	cfg := ai.LoadConfig()

	context := buildAIContext(r)

	body, _ := json.Marshal(struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Stream bool `json:"stream"`
	}{
		Model: cfg.Model,
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			{Role: "system", Content: reportPrompt},
			{Role: "user", Content: context},
		},
		Stream: false,
	})

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(cfg.Endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("LLM returned %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	parseResponse(result.Message.Content, r)
	return nil
}

func buildAIContext(r *ReportData) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Healt Score: %.0f/100\n", r.HealthScore))
	sb.WriteString(fmt.Sprintf("Risks: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d\n",
		r.Risks["CRITICAL"], r.Risks["HIGH"], r.Risks["MEDIUM"], r.Risks["LOW"]))
	sb.WriteString(fmt.Sprintf("Estimated waste: $%.0f/month\n", r.TotalWaste))

	if r.Trend != nil {
		sb.WriteString(
			fmt.Sprintf(
				"Trend: %d new, %d resolved, %d ongoing\n",
				r.Trend.New,
				r.Trend.Resolved,
				r.Trend.Ongoing,
			),
		)
	}

	for _, c := range r.Compliance {
		sb.WriteString(fmt.Sprintf("Compliance (%s): %.0f%%\n", c.Label, c.Percent))
	}

	if len(r.TopSecurity) > 0 {
		sb.WriteString("\nTop security issues:\n")
		for _, f := range r.TopSecurity {
			sb.WriteString(
				fmt.Sprintf("- [%s] %s/%s: %s\n", f.RiskLevel, f.Service, f.Check, f.Detail),
			)
		}
	}
	if len(r.TopCost) > 0 {
		sb.WriteString("\nTop cost issues:\n")
		for _, f := range r.TopCost {
			sb.WriteString(
				fmt.Sprintf(
					"- [%s] %s/%s: %s ($%.0f/mo)\n",
					f.RiskLevel,
					f.Service,
					f.Check,
					f.Detail,
					f.EstimatedMonthlyCost,
				),
			)
		}
	}
	return sb.String()
}

func parseResponse(content string, r *ReportData) {
	lines := strings.Split(content, "\n")
	var section string
	var summary []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SUMMARY:") {
			section = "summary"
			after := strings.TrimSpace(strings.TrimPrefix(trimmed, "SUMMARY:"))
			if after != "" {
				summary = append(summary, after)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "ACTIONS:") ||
			strings.HasPrefix(trimmed, "RECOMMENDED ACTIONS:") {
			section = "actions"
			continue
		}
		switch section {
		case "summary":
			if trimmed != "" {
				summary = append(summary, trimmed)
			}
		case "actions":
			if trimmed != "" {
				// Strip leading "1. ", "2. ", "3. " etc.
				if len(trimmed) > 2 && trimmed[0] >= '0' && trimmed[0] <= '9' && trimmed[1] == '.' {
					trimmed = strings.TrimSpace(trimmed[2:])
				}
				r.AIRecommendations = append(r.AIRecommendations, trimmed)
			}
		}
	}
	r.AISummary = strings.Join(summary, " ")
}
