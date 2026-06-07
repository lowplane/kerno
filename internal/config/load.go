// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// NewViper returns a viper instance wired to resolve KERNO_* environment
// variables for every configuration key.
//
// Viper's AutomaticEnv only resolves a key at Get time for keys it already
// knows about, and Unmarshal walks the known-key set (AllKeys). Without any
// defaults, file, or bindings registered, that set is empty, so KERNO_* env
// vars silently resolve to nothing. To make the documented precedence
// (flags > env > file > defaults) hold for the whole env tier, we register
// every key from Default() as a viper default. Defaults are the lowest
// precedence tier, so a changed flag, an env var, and a config file all still
// override them. Because the keys are derived from the struct's mapstructure
// tags, any future field is covered automatically.
func NewViper() *viper.Viper {
	v := viper.New()

	// Environment variables: KERNO_LOG_LEVEL, KERNO_PROMETHEUS_ADDR, etc.
	v.SetEnvPrefix("KERNO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Register every key so AutomaticEnv and Unmarshal can see them.
	defaults := make(map[string]any)
	flattenDefaults("", reflect.ValueOf(*Default()), defaults)
	for key, val := range defaults {
		v.SetDefault(key, val)
	}

	return v
}

// flattenDefaults walks a config struct and records each leaf field under its
// dotted mapstructure key (e.g. "ai.api_key",
// "doctor.thresholds.tcp_retransmit_pct") in out. Nested structs are recursed
// into; everything else (including time.Duration, whose Kind is Int64) is a
// leaf.
func flattenDefaults(prefix string, rv reflect.Value, out map[string]any) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)

		name, _, _ := strings.Cut(field.Tag.Get("mapstructure"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(field.Name)
		}

		key := name
		if prefix != "" {
			key = prefix + "." + name
		}

		fv := rv.Field(i)
		if fv.Kind() == reflect.Struct {
			flattenDefaults(key, fv, out)
			continue
		}
		out[key] = fv.Interface()
	}
}
