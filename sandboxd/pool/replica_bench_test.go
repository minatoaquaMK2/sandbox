package pool

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cocoonstack/sandbox/sandboxd/archives"
	"github.com/cocoonstack/sandbox/sandboxd/config"
	"github.com/cocoonstack/sandbox/sandboxd/types"
)

const replicaScanProbe = "sb_0000000000000001"

func BenchmarkReplicaScan(b *testing.B) {
	for _, checkpoints := range []bool{false, true} {
		for _, mode := range []string{"none", "one", "detach"} {
			b.Run(replicaScanCaseName(checkpoints, mode), func(b *testing.B) {
				f := newReplicaScanFixture(b, mode, checkpoints)
				b.ReportAllocs()
				for b.Loop() {
					b.StopTimer()
					f.prepareIteration()
					b.StartTimer()
					f.manager.replicateOnce(b.Context())
					b.StopTimer()
					if err := f.stateError(); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				b.ReportMetric(5000, "asserted-claims/op")
				b.ReportMetric(float64(f.skipped), "volume-skips/op")
			})
		}
	}
}

func TestReplicaScanShape(t *testing.T) {
	for _, checkpoints := range []bool{false, true} {
		for _, mode := range []string{"none", "one", "detach"} {
			t.Run(replicaScanCaseName(checkpoints, mode), func(t *testing.T) {
				f := newReplicaScanFixture(t, mode, checkpoints)
				f.prepareIteration()
				f.manager.replicateOnce(t.Context())
				if err := f.stateError(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReplicaScanRejectsNoOp(t *testing.T) {
	f := newReplicaScanFixture(t, "one", true)
	f.prepareIteration()
	f.manager.replicateOnce(t.Context())
	if err := f.stateError(); err != nil {
		t.Fatal(err)
	}
	f.prepareIteration()
	noOp := func() {}
	noOp()
	err := f.stateError()
	if err == nil || !strings.Contains(err.Error(), "probe tried stayed zero") {
		t.Fatalf("no-op control rejected for wrong reason: %v", err)
	}
	t.Logf("no-op rejected after a successful real scan: %v", err)
}

type forbiddenReplicaRegistry struct{ archives.Registry }

type replicaScanFixture struct {
	manager *Manager
	want    map[string]replicaState
	skipped int
}

func newReplicaScanFixture(tb testing.TB, mode string, checkpoints bool) replicaScanFixture {
	tb.Helper()
	m := newTestManager(tb, newFakeEngine(), config.PoolSpec{PoolKey: testKey})
	m.claimed = benchClaims(5000)
	first := m.claimed["sb_0000000000000000"]
	if checkpoints {
		for id, sb := range m.claimed {
			sb.ReplicaCk = "ck_" + id[3:]
		}
		if mode != "none" {
			first.ReplicaCk = ""
			m.claimed[replicaScanProbe].ReplicaPending = "ck_ffffffffffffffff"
		}
	}
	if mode != "none" {
		first.Volumes = []types.Volume{{Name: "bench-data", Mount: "/mnt/data"}}
		first.VolumesWant = first.Volumes
	}
	if err := m.store.save(m.claimed); err != nil {
		tb.Fatal(err)
	}
	wantCheckpoints := 0
	if checkpoints {
		wantCheckpoints = 5000
	}
	if got := len(m.store.checkpointReferences()); got != wantCheckpoints {
		tb.Fatalf("checkpoint references=%d, want %d", got, wantCheckpoints)
	}
	if mode != "none" && first.HasReplica() {
		tb.Fatal("volume owner has a replica that would launch asynchronous retirement")
	}
	if mode == "detach" {
		m.mu.Lock()
		first.Volumes, first.VolumesWant = nil, nil
		m.store.set(first)
		m.mu.Unlock()
	}
	v := *m.view.Load()
	v.poolReplicate = map[types.PoolKey]time.Duration{first.PolicyKey(): 24 * time.Hour}
	m.view.Store(&v)
	m.archives = forbiddenReplicaRegistry{}
	m.replicas = make(map[string]replicaState, 5001)
	f := replicaScanFixture{manager: m, want: make(map[string]replicaState, 5000)}
	tried := time.Now()
	for id := range m.claimed {
		st := replicaState{tried: tried}
		if id == first.ID && (mode == "one" || mode == "detach") {
			st = replicaState{skipLogged: true}
			f.skipped++
		}
		m.replicas[id], f.want[id] = st, st
	}
	return f
}

func (f replicaScanFixture) prepareIteration() {
	f.manager.replicas["replica-scan-unclaimed-marker"] = replicaState{}
	f.manager.replicas[replicaScanProbe] = replicaState{}
}

func (f replicaScanFixture) stateError() error {
	m := f.manager
	if m.replicas[replicaScanProbe].tried.IsZero() {
		return fmt.Errorf("replicateOnce did not visit ordinary claim: probe tried stayed zero")
	}
	if _, stale := m.replicas["replica-scan-unclaimed-marker"]; stale {
		return fmt.Errorf("replicateOnce did not rebuild states: unclaimed marker survived")
	}
	if len(m.replicas) != 5000 || m.replicating.Load() {
		return fmt.Errorf("replicateOnce did not synchronously rebuild 5000 states: states=%d busy=%t", len(m.replicas), m.replicating.Load())
	}
	for id, want := range f.want {
		st, ok := m.replicas[id]
		if !ok || st.skipLogged != want.skipLogged || id != replicaScanProbe && !st.tried.Equal(want.tried) {
			return fmt.Errorf("claim %s replica state=%+v present=%t want=%+v", id, st, ok, want)
		}
	}
	return nil
}

func replicaScanCaseName(checkpoints bool, mode string) string {
	refs := "0"
	if checkpoints {
		refs = "5000"
		if mode != "none" {
			refs += "-balanced-volume-owner-unpinned"
		}
	}
	return fmt.Sprintf("claims=5000/checkpoints=%s/volumes=%s", refs, mode)
}
