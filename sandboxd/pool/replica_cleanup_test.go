package pool

import (
	"errors"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestFailoverDisabledKeepsStateAndRefusesLiveWriter(t *testing.T) {
	for _, state := range strandedStates {
		t.Run(state.name, func(t *testing.T) {
			m, sb, _ := restartStranded(t, state)
			if err := m.Wake(t.Context(), sb.ID, Cred{Token: sb.Token}); err != nil {
				t.Fatal(err)
			}
			requireStrandedWriter(t, m, sb)
		})
	}
}

func requireStrandedWriter(t *testing.T, m *Manager, sb *types.Sandbox) {
	t.Helper()
	if err := m.RegisterVolume(t.Context(), "data", types.VolumeRegistration{Path: writeVolumeImage(t, "data", "original"), Writable: true}); err != nil {
		t.Fatal(err)
	}
	want := []types.Volume{{Name: "data", Mode: types.VolumeModeRW, AttachOnly: true}}
	view, err := m.SetVolumes(t.Context(), sb.ID, "", want)
	if !errors.Is(err, ErrReplicaStranded) || len(view.Volumes) != 0 || len(view.VolumesWant) != 0 {
		t.Fatalf("live writer on stranded failover state: err=%v volumes=%v want=%v", err, view.Volumes, view.VolumesWant)
	}
}
