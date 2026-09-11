package pool

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/config"
	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestDynamicVolumeCatalogAcceptsOnlyImmutableRegularImages(t *testing.T) {
	directory := t.TempDir()
	validName := "kb-0123456789abcdef"
	validPath := filepath.Join(directory, validName+".img")
	if err := os.WriteFile(validPath, []byte("knowledge"), 0o444); err != nil {
		t.Fatal(err)
	}
	writableName := "kb-1111111111111111"
	if err := os.WriteFile(filepath.Join(directory, writableName+".img"), []byte("mutable"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkName := "kb-2222222222222222"
	if err := os.Symlink(validPath, filepath.Join(directory, symlinkName+".img")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "not-a-volume.img"), []byte("ignored"), 0o444); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(t.Context(), &config.Config{
		DataDir: t.TempDir(),
		VolumeDirectory: &config.VolumeDirectorySpec{
			Path: directory, DirectIO: types.DirectIOOff, Tenants: []string{"acme"},
		},
	}, newFakeEngine(), testSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.VolumeNames(); !slices.Equal(got, []string{validName}) {
		t.Fatalf("VolumeNames=%v, want only immutable regular image", got)
	}
	if local, err := m.VolumePlacement(testKey, "acme", []string{validName}); err != nil || !local {
		t.Fatalf("allowed placement=(%v,%v)", local, err)
	}
	if _, err := m.VolumePlacement(testKey, "beta", []string{validName}); !errors.Is(err, ErrVolumeUnavailable) {
		t.Fatalf("forbidden placement error=%v", err)
	}
	for _, rejected := range []string{writableName, symlinkName} {
		if _, err := m.resolveVolumes(t.Context(), "acme", []types.Volume{{Name: rejected}}); err == nil {
			t.Fatalf("resolveVolumes accepted %s", rejected)
		}
	}
}

func TestAttachDetachVolumesAreIdempotentAndPersisted(t *testing.T) {
	path := writeVolumeImage(t, "knowledge.img", "knowledge")
	eng := newFakeEngine()
	m := newVolumeManager(t, eng, []config.VolumeSpec{{Name: "knowledge", Path: path, Writable: true}})
	sb, err := m.ClaimProvision(t.Context(), testKey, 0, "acme", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	eng.volumeOps = nil
	eng.mu.Unlock()

	want := []types.Volume{{Name: "knowledge", Mount: "/agent-context/bases/runbooks"}}
	got, err := m.AttachVolumes(t.Context(), sb.ID, Cred{Token: sb.Token}, want)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("AttachVolumes=(%v,%v)", got, err)
	}
	if _, repeatErr := m.AttachVolumes(t.Context(), sb.ID, Cred{Token: sb.Token}, want); repeatErr != nil {
		t.Fatalf("idempotent AttachVolumes: %v", repeatErr)
	}
	if holders := volumeHoldersOf(m, "knowledge"); holders != (volumeHolders{readers: 1}) {
		t.Fatalf("volume admission after attach=%+v, want one reader", holders)
	}
	if _, conflictErr := m.AttachVolumes(t.Context(), sb.ID, Cred{Token: sb.Token}, []types.Volume{{
		Name: "knowledge", Mode: types.VolumeModeRW,
	}}); !errors.Is(conflictErr, ErrBadVolume) {
		t.Fatalf("writable live attach error=%v, want ErrBadVolume", conflictErr)
	}
	eng.mu.Lock()
	if wantOps := []string{
		"attach:knowledge", "mount:knowledge:/agent-context/bases/runbooks",
	}; !slices.Equal(eng.volumeOps, wantOps) {
		t.Fatalf("attach operations=%v, want %v", eng.volumeOps, wantOps)
	}
	eng.volumeOps = nil
	eng.mu.Unlock()
	persisted, err := m.store.load()
	if err != nil || !slices.Equal(persisted[sb.ID].Volumes, want) {
		t.Fatalf("persisted volumes=%v err=%v", persisted[sb.ID].Volumes, err)
	}

	got, err = m.DetachVolumes(t.Context(), sb.ID, Cred{Token: sb.Token}, []string{"knowledge"})
	if err != nil || len(got) != 0 {
		t.Fatalf("DetachVolumes=(%v,%v)", got, err)
	}
	if _, repeatErr := m.DetachVolumes(t.Context(), sb.ID, Cred{Token: sb.Token}, []string{"knowledge"}); repeatErr != nil {
		t.Fatalf("idempotent DetachVolumes: %v", repeatErr)
	}
	eng.mu.Lock()
	if wantOps := []string{
		"umount:/agent-context/bases/runbooks", "detach:knowledge",
	}; !slices.Equal(eng.volumeOps, wantOps) {
		t.Fatalf("detach operations=%v, want %v", eng.volumeOps, wantOps)
	}
	eng.mu.Unlock()
	persisted, err = m.store.load()
	if err != nil || len(persisted[sb.ID].Volumes) != 0 {
		t.Fatalf("persisted detached volumes=%v err=%v", persisted[sb.ID].Volumes, err)
	}
	if _, authErr := m.AttachVolumes(t.Context(), sb.ID, Cred{Token: "wrong"}, want); !errors.Is(authErr, ErrUnknownSandbox) {
		t.Fatalf("wrong-token error=%v", authErr)
	}
	if holders := volumeHoldersOf(m, "knowledge"); holders != (volumeHolders{}) {
		t.Fatalf("volume admission after detach=%+v, want empty", holders)
	}
	raw, err := os.ReadFile(filepath.Join(m.dataDir, "usage.jsonl"))
	if err != nil || !strings.Contains(string(raw), "\"ev\":\"volume_attach\"") ||
		!strings.Contains(string(raw), "\"ev\":\"volume_detach\"") {
		t.Fatalf("usage journal=%q err=%v", raw, err)
	}
}
