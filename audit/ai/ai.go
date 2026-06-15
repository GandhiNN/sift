package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sift/audit"
)

type Config struct {
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

func LoadConfig() Config {
	cfg := Config{
		Endpoint: "http://localhost:11434/api/chat", // default
		Model:    "phi3:3.8b",                       // default
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
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

func BuildContext(grouped map[string][]audit.Finding) string {
	var sb strings.Builder
	total := 0

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
		total += len(relevant)
		sb.WriteString(
			fmt.Sprintf("## %s findings (%d issues):\n", strings.ToUpper(module), len(relevant)),
		)
		b, _ := json.MarshalIndent(relevant, "", "  ")
		sb.Write(b)
		sb.WriteString("\n\n")
	}

	if total == 0 {
		return "No issues found. All checks passed."
	}
	return sb.String()
}

func AnalyzeWithContext(cfg Config, context, question string) (string, error) {
	messages := []message{
		{
			Role:    "system",
			Content: "You are an AWS security and cost expert. Analyze the following audit findings and provide actionable recommendations. Be concise and prioritize by risk level.",
		},
		{Role: "user", Content: context + "\n\n" + question},
	}

	body, _ := json.Marshal(chatRequest{
		Model:    cfg.Model,
		Messages: messages,
		Stream:   false,
	})

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(cfg.Endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM returned %d: %s", resp.StatusCode, string(b))
	}

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return result.Message.Content, nil
}
