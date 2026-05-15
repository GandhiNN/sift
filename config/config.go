package config

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func BuildConfig(ctx context.Context, profile string) (aws.Config, error) {
	slog.Info("loading config", "profile", profile)

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf(
			"failed to load AWS config for profile %s: %w",
			profile,
			err,
		)
	}
	slog.Info("loaded profile", "profile", profile)
	return cfg, nil
}
