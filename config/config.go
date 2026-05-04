package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"gopkg.in/ini.v1"
)

func getCredentialsPath() (string, error) {
	if p := os.Getenv("SSO_CREDENTIAL_PATH"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "credentials"), nil
}

func getProfiles(path string) ([]string, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("credentials file not found: %w", err)
	}
	return cfg.SectionStrings(), nil
}

func BuildConfig(ctx context.Context, profile string) (aws.Config, error) {
	credPath, err := getCredentialsPath()
	if err != nil {
		return aws.Config{}, err
	}
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		return aws.Config{}, fmt.Errorf("credentials file not found: %s", credPath)
	}
	slog.Info("loading credentials", "path", credPath)

	profiles, err := getProfiles(credPath)
	if err != nil {
		return aws.Config{}, err
	}
	found := false
	for _, p := range profiles {
		if p == profile {
			found = true
			break
		}
	}
	if !found {
		return aws.Config{}, fmt.Errorf("profile not found: %s", profile)
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedCredentialsFiles([]string{credPath}),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	slog.Info("loaded profile", "profile", profile, "path", credPath)
	return cfg, nil
}
