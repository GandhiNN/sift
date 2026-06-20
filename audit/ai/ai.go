package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sift/audit"
)

type Config struct {
	Endpoint string            `json:"endpoint"`
	Model    string            `json:"model"`
	Prompts  map[string]string `json:"prompts"`
}

const defaultPrompt = "You are an AWS infrastructure expert. Analyze ONLY the provided audit findings. Do not suggest actions outside the scope of the findings shown. Be concise and prioritize by risk level."

func (c Config) GetPrompt(name string) string {
	if name != "" && c.Prompts != nil {
		if p, ok := c.Prompts[name]; ok {
			return p
		}
	}
	if c.Prompts != nil {
		if p, ok := c.Prompts["default"]; ok {
			return p
		}
	}
	return defaultPrompt
}

var riskOrder = map[string]int{
	"MINIMAL":  0,
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

func LoadConfig() Config {
	cfg := Config{
		Endpoint: "http://localhost:11434/v1/chat/completions", // default
		Model:    "phi3:3.8b",                                  // default
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "ai.json"))
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
		Delta   message `json:"delta"`
	} `json:"choices"`
	Usage *Usage `json:"usage,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Stats holds telemtery from an AI call.
type Stats struct {
	Model            string
	PromptTokens     int
	CompletionTokens int
	DurationMs       int64
}

func BuildContext(grouped map[string][]audit.Finding) string {
	var sb strings.Builder

	// Summary header
	risks := map[string]int{}
	var totalWaste float64
	var totalIssues int
	var totalResources int
	for _, findings := range grouped {
		for _, f := range findings {
			totalResources++
			if f.Status != "PASS" {
				totalIssues++
				risks[f.RiskLevel]++
				totalWaste += f.EstimatedMonthlyCost
			}
		}
	}

	sb.WriteString("### Account Summary:\n")
	sb.WriteString(fmt.Sprintf("Total resources scanned: %d\n", totalResources))
	sb.WriteString(fmt.Sprintf("Total issues: %d (CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)\n",
		totalIssues, risks["CRITICAL"], risks["HIGH"], risks["MEDIUM"], risks["LOW"]))
	if totalWaste > 0 {
		sb.WriteString(fmt.Sprintf("Estimated monthly waste: $%.0f\n", totalWaste))
	}
	compliant := totalResources - totalIssues
	if totalResources > 0 {
		sb.WriteString(
			fmt.Sprintf(
				"Compliance: %.0f%% (%d of %d resources clean)\n",
				float64(compliant)/float64(totalResources)*100,
				compliant,
				totalResources,
			),
		)
	}
	sb.WriteString("\n")

	// Per-module top findings
	for module, findings := range grouped {
		var relevant []audit.Finding
		for _, f := range findings {
			if f.Status != "PASS" {
				relevant = append(relevant, f)
			}
		}
		if len(relevant) == 0 {
			continue
		}
		sort.Slice(relevant, func(i, j int) bool {
			return riskOrder[relevant[i].RiskLevel] > riskOrder[relevant[j].RiskLevel]
		})
		if len(relevant) > 10 {
			relevant = relevant[:10]
		}
		sb.WriteString(
			fmt.Sprintf(
				"## %s findings (top %d of %d issues):\n",
				strings.ToUpper(module),
				len(relevant),
				risks[module],
			),
		)
		for _, f := range relevant {
			line := fmt.Sprintf(
				"- [%s] %s/%s: %s (%s)",
				f.RiskLevel,
				f.Service,
				f.Check,
				f.Detail,
				f.ResourceID,
			)
			if f.EstimatedMonthlyCost > 0 {
				line += fmt.Sprintf(" [$%.0f/mo]", f.EstimatedMonthlyCost)
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
		sb.WriteString("\n")
	}

	if totalIssues == 0 {
		return "No issues found. All checks passed."
	}
	return sb.String()
}

func AnalyzeWithContext(
	cfg Config,
	context, question, promptName string,
	stream io.Writer,
) (*Stats, error) {
	start := time.Now()
	messages := []message{
		{Role: "system", Content: cfg.GetPrompt(promptName)},
		{Role: "user", Content: context + "\n\n" + question},
	}

	streaming := stream != nil
	body, _ := json.Marshal(chatRequest{
		Model:    cfg.Model,
		Messages: messages,
		Stream:   streaming,
	})

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Post(cfg.Endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LLM returned %d: %s", resp.StatusCode, string(b))
	}

	stats := &Stats{Model: cfg.Model}

	if streaming {
		decoder := json.NewDecoder(resp.Body)
		for decoder.More() {
			var chunk chatResponse
			if err := decoder.Decode(&chunk); err != nil {
				break
			}
			if len(chunk.Choices) > 0 {
				fmt.Fprint(stream, chunk.Choices[0].Delta.Content)
			}
			if chunk.Usage != nil {
				stats.PromptTokens = chunk.Usage.PromptTokens
				stats.CompletionTokens = chunk.Usage.CompletionTokens
			}
		}
		fmt.Fprintln(stream)
	} else {
		var result chatResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		if len(result.Choices) > 0 {
			fmt.Fprintln(stream, result.Choices[0].Message.Content)
		}
		if result.Usage != nil {
			stats.PromptTokens = result.Usage.PromptTokens
			stats.CompletionTokens = result.Usage.CompletionTokens
		}
	}

	stats.DurationMs = time.Since(start).Milliseconds()
	return stats, nil
}
