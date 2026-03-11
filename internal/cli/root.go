// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package cli defines all Cobra commands for the kerno CLI.
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/lowplane/kerno/internal/config"
)

var (
	cfgFile string
	cfg     *config.Config
)

// New creates the root command and registers all sub-commands.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "kerno",
		Short: "Kernel-level observability engine for Linux",
		Long: `Kerno is an eBPF-based kernel observability engine that provides
real-time diagnostics, performance monitoring, and actionable insights
for Linux systems and Kubernetes clusters.

Run 'kerno doctor' for a 30-second automated kernel diagnostic.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initConfig(cmd)
		},
	}

	// Global flags.
	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default: /etc/kerno/config.yaml)")
	pf.String("log-level", "info", "log level: debug, info, warn, error")
	pf.String("log-format", "text", "log format: text, json")
	pf.String("output", "pretty", "output format: pretty, json")
	pf.Bool("no-color", false, "disable colored output")

	// Register sub-commands.
	root.AddCommand(
		newDoctorCmd(),
		newVersionCmd(),
		newStartCmd(),
	)

	return root
}

// initConfig reads the config file and environment variables.
func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	// Config file discovery.
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/kerno")
		v.AddConfigPath("$HOME/.kerno")
		v.AddConfigPath(".")
	}

	// Environment variables: KERNO_LOG_LEVEL, KERNO_PROMETHEUS_ADDR, etc.
	v.SetEnvPrefix("KERNO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Bind CLI flags to viper.
	if err := v.BindPFlag("log_level", cmd.Root().PersistentFlags().Lookup("log-level")); err != nil {
		return fmt.Errorf("binding log-level flag: %w", err)
	}
	if err := v.BindPFlag("log_format", cmd.Root().PersistentFlags().Lookup("log-format")); err != nil {
		return fmt.Errorf("binding log-format flag: %w", err)
	}

	// Read config file (not an error if it doesn't exist).
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Only error if the file exists but can't be parsed.
			if cfgFile != "" {
				return fmt.Errorf("reading config file: %w", err)
			}
		}
	}

	// Unmarshal into our typed config.
	cfg = config.Default()
	if err := v.Unmarshal(cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize the global logger.
	initLogger(cfg.LogLevel, cfg.LogFormat)

	return nil
}

// initLogger configures the global slog logger.
func initLogger(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}
