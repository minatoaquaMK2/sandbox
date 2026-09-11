package config

import (
	"strings"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestLoadAcceptsContentAddressedVolumeDirectory(t *testing.T) {
	path := writeConfig(t, `{
		"api_token":"root",
		"pools":[],
		"tenants":[{"name":"platform","token":"tenant-token"}],
		"volume_directory":{
			"path":"/var/lib/knowledge-volumes",
			"tenants":["platform"]
		}
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VolumeDirectory == nil ||
		cfg.VolumeDirectory.DirectIO != types.DirectIOOff ||
		cfg.VolumeDirectory.Path != "/var/lib/knowledge-volumes" {
		t.Fatalf("volume_directory=%+v", cfg.VolumeDirectory)
	}
}

func TestLoadRejectsUnsafeVolumeDirectory(t *testing.T) {
	for _, body := range []string{
		`{"pools":[],"volume_directory":{"path":"relative"}}`,
		`{"pools":[],"volume_directory":{"path":"/"}}`,
		`{"pools":[],"volume_directory":{"path":"/safe","directio":"yes"}}`,
		`{"pools":[],"volume_directory":{"path":"/safe","tenants":["missing"]}}`,
	} {
		if _, err := Load(writeConfig(t, body)); err == nil ||
			!strings.Contains(err.Error(), "volume_directory") {
			t.Fatalf("Load(%s) error=%v", body, err)
		}
	}
}
