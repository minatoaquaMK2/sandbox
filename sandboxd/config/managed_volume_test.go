package config

import (
	"path/filepath"
	"testing"
)

func TestManagedVolumeStoreExcludesStartupCleanupPaths(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{filepath.Join(data, "managed"), true},
		{filepath.Join(root, "outside"), true},
		{filepath.Join(data, "readers-backup", "managed"), true},
		{filepath.Join(data, "forks", "managed"), true},
		{filepath.Join(data, "readers"), false},
		{filepath.Join(data, "readers", "managed"), false},
		{filepath.Join(data, "fork-state"), false},
		{filepath.Join(data, "fork-state", "managed"), false},
		{filepath.Join(data, "goldens"), false},
		{filepath.Join(data, "goldens", "managed"), false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			cfg := Config{DataDir: data, ManagedVolumeDir: tc.path, APIToken: "root"}
			err := cfg.ValidateManagedVolumeStore()
			if (err == nil) != tc.allow {
				t.Fatalf("path %q accepted=%v, want %v: %v", tc.path, err == nil, tc.allow, err)
			}
		})
	}
}
