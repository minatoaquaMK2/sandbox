package pool

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestReplicaScanWaitsForDetachAcknowledgment(t *testing.T) {
	m, c := newReplicaVolumeManager(t)
	sb := mustClaim(t, m, testKey)
	attached := mustClaim(t, m, testKey)
	ordinary := mustClaim(t, m, testKey)
	for _, owner := range []*types.Sandbox{sb, attached} {
		if _, err := m.SetVolumes(t.Context(), owner.ID, "", []types.Volume{{Name: "data"}}); err != nil {
			t.Fatal(err)
		}
	}
	m.store.recommitting.Store(true)
	eng := m.eng.(*fakeEngine)
	tmp := m.store.path + ".tmp"
	eng.liveVolumeHook = func(verb string) error {
		if verb == "detach" {
			return os.Mkdir(tmp, 0o700)
		}
		return nil
	}
	view, err := m.SetVolumes(t.Context(), sb.ID, "", nil)
	eng.liveVolumeHook = nil
	if err == nil || len(view.Volumes) != 0 || len(view.VolumesWant) != 0 {
		t.Fatalf("detach did not fail after device removal: %+v, %v", view, err)
	}
	m.replicateOnce(t.Context())
	if m.replicating.Load() || !m.replicas[sb.ID].skipLogged || !m.replicas[attached.ID].skipLogged || m.replicas[ordinary.ID].tried.IsZero() || m.replicas[ordinary.ID].skipLogged {
		t.Fatalf("scan failed to distinguish detached, attached, and ordinary claims: %+v", m.replicas)
	}
	if err = m.replicate(t.Context(), sb); !errors.Is(err, ErrVolumeCapture) {
		t.Fatalf("single-owner capture ignored retained attachment: %v", err)
	}
	if sb.HasReplica() || len(eng.snapSaves) != 0 {
		t.Fatal("pending detach published a replica")
	}
	if err = os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	if err = m.store.commit(m.store.mark()); err != nil {
		t.Fatal(err)
	}
	m.replicateOnce(t.Context())
	if st := m.replicas[sb.ID]; st.skipLogged || st.tried.IsZero() {
		t.Fatalf("acknowledged detach stayed skipped: %+v", st)
	}
	m.replicas[sb.ID] = replicaState{tried: time.Now().Add(-time.Hour)}
	m.replicateOnce(t.Context())
	waitFor(t, func() bool { return !m.replicating.Load() })
	rec, ok, err := c.reg.Get(t.Context(), sb.ID)
	if err != nil || !ok || rec.Consumed || rec.Checkpoint == "" || !sb.HasReplica() {
		t.Fatalf("acknowledged detach did not permit future replication: %+v, %t, %v", rec, ok, err)
	}
}
