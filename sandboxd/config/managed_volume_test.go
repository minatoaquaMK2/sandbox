package config

import (
	"os"
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

func TestManagedVolumeStoreResolvesDataDirectoryAliases(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for _, tc := range []struct {
		name, data, managed string
		allow               bool
	}{
		{"alias-readers", alias, filepath.Join(real, "readers", "managed"), false},
		{"alias-goldens", alias, filepath.Join(real, "goldens"), false},
		{"alias-fork", alias, filepath.Join(real, "fork-persistent"), false},
		{"alias-new-suffix", filepath.Join(alias, "new", "data"), filepath.Join(real, "new", "data", "readers", "managed"), false},
		{"alias-safe", alias, filepath.Join(real, "managed"), true},
		{"relative", "real", filepath.Join(real, "readers", "managed"), false},
		{"relative-safe", "real", filepath.Join(real, "readers-safe"), true},
		{"empty", "", filepath.Join(root, "fork-store"), false},
		{"empty-safe", "", filepath.Join(root, "managed"), true},
		{"ancestor", filepath.Join(real, "data"), real, true},
		{"same-root", real, real, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{DataDir: tc.data, ManagedVolumeDir: tc.managed, APIToken: "root"}
			err := cfg.ValidateManagedVolumeStore()
			if (err == nil) != tc.allow {
				t.Fatalf("data=%q managed=%q accepted=%v, want %v: %v", tc.data, tc.managed, err == nil, tc.allow, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(real, "new")); !os.IsNotExist(err) {
		t.Fatalf("validation created data directories: %v", err)
	}
}
