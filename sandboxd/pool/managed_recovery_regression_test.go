package pool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestManagedQuarantineRemovalSurvivesFailedRetirementRestart(t *testing.T) {
	for _, syncClaims := range []bool{false, true} {
		for _, published := range []bool{false, true} {
			name := "async"
			if syncClaims {
				name = "sync"
			}
			if published {
				name += "/published"
			} else {
				name += "/unpublished"
			}
			t.Run(name, func(t *testing.T) {
				cfg := managedConfig(t)
				cfg.SyncClaims = syncClaims
				e := newManagedEngine()
				m := openManagedTest(t, cfg, e)
				createManagedTest(t, m, "data")
				sb, err := m.ClaimProvision(t.Context(), testKey, managedOptions("data"))
				if err != nil {
					t.Fatal(err)
				}
				sb.Key.Net = types.NetEgress
				if err := m.store.commit(m.store.set(sb)); err != nil {
					t.Fatal(err)
				}
				e.falseRemove.Store(true)
				m.managed.commitFile = func(path string, raw []byte) error {
					if published {
						if err := writeVolumeSnapshot(path, raw); err != nil {
							return err
						}
					}
					return errors.New("retirement persistence fault")
				}
				if m.quarantineClaim(t.Context(), sb) {
					t.Fatal("ineffective removal reported success")
				}
				waitFor(t, m.store.synced)
				if err := m.Close(); err != nil {
					t.Fatal(err)
				}
				m = openManagedTest(t, cfg, e)
				if err := m.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
				_, err = m.ClaimProvision(t.Context(), testKey, managedOptions("data"))
				requireVolumeStatus(t, err, 409)
				e.falseRemove.Store(false)
				m.retryRemovals(t.Context()).Wait()
				if _, present, err := e.Inspect(t.Context(), sb.VMName); err != nil || present {
					t.Fatalf("quarantined VM survived removal retry after restart: present=%v err=%v", present, err)
				}
				replacement, err := m.ClaimProvision(t.Context(), testKey, managedOptions("data"))
				if err != nil {
					t.Fatalf("confirmed removal did not free managed disk: %v", err)
				}
				if err := m.Release(t.Context(), replacement.ID, Cred{Operator: true}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestManagedOrdinaryFailedClaimRetainsOwnershipOnRestart(t *testing.T) {
	cfg := managedConfig(t)
	e := newManagedEngine()
	m := openManagedTest(t, cfg, e)
	createManagedTest(t, m, "data")
	sb, err := m.ClaimProvision(t.Context(), testKey, managedOptions("data"))
	if err != nil {
		t.Fatal(err)
	}
	sb.Failed = "ordinary failure requiring explicit release"
	if err := m.store.commit(m.store.set(sb)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m = openManagedTest(t, cfg, e)
	if err := m.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	m.retryRemovals(t.Context()).Wait()
	if _, present, err := e.Inspect(t.Context(), sb.VMName); err != nil || !present {
		t.Fatalf("ordinary failed claim removed: %v %v", present, err)
	}
	_, err = m.ClaimProvision(t.Context(), testKey, managedOptions("data"))
	requireVolumeStatus(t, err, 409)
	if err := m.Release(t.Context(), sb.ID, Cred{Operator: true}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedStartupCleansDeadOrphansAndRefusesUnknownProcess(t *testing.T) {
	for _, tc := range []struct {
		name              string
		pid               int
		stopped           bool
		processError      error
		allow             bool
		ineffectiveRemove bool
	}{
		{name: "stopped-absent-pid", pid: 12345, stopped: true, processError: os.ErrNotExist, allow: true},
		{name: "running-absent-pid", pid: 12345, processError: os.ErrNotExist, allow: true},
		{name: "stopped-zero-pid", stopped: true, allow: true},
		{name: "running-zero-pid"},
		{name: "unreadable-pid", pid: 12345, stopped: true, processError: os.ErrPermission},
		{name: "ineffective-remove", pid: 12345, stopped: true, processError: os.ErrNotExist, ineffectiveRemove: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := managedConfig(t)
			e := newManagedEngine()
			m := openManagedTest(t, cfg, e)
			createManagedTest(t, m, "data")
			const name = "sbx-stale-orphan"
			e.mu.Lock()
			e.vms[name] = "/fake/vsock"
			e.stopped[name] = tc.stopped
			e.pids[name] = tc.pid
			e.mu.Unlock()
			if tc.processError != nil {
				m.managed.process = func(int) (processIdentity, error) { return processIdentity{}, tc.processError }
			} else {
				m.managed.process = readProcessIdentity
			}
			e.falseRemove.Store(tc.ineffectiveRemove)
			err := m.Reconcile(t.Context())
			if tc.allow {
				if err != nil {
					t.Fatalf("dead orphan blocked startup: %v", err)
				}
				if _, present, err := e.Inspect(t.Context(), name); err != nil || present {
					t.Fatalf("dead orphan survived cleanup: %v %v", present, err)
				}
			} else {
				requireVolumeStatus(t, err, 503)
			}
			if tc.processError == os.ErrPermission || (!tc.stopped && tc.pid == 0) {
				e.mu.Lock()
				defer e.mu.Unlock()
				if len(e.removes) != 0 {
					t.Fatalf("unproven process removed: %v", e.removes)
				}
			}
		})
	}
}

func TestManagedStoreRejectsSweepOwnedPathsBeforeCreatingFiles(t *testing.T) {
	for _, rel := range []string{"readers", "readers/managed", "fork-persistent", "fork-persistent/managed", "goldens", "goldens/managed"} {
		t.Run(rel, func(t *testing.T) {
			cfg := managedConfig(t)
			cfg.ManagedVolumeDir = filepath.Join(cfg.DataDir, rel)
			m, err := NewManager(t.Context(), cfg, newManagedEngine(), testSecrets(t), testBackends(t, cfg))
			if err == nil {
				m.Close()
				t.Fatal("accepted managed store inside startup cleanup namespace")
			}
			if _, err := os.Stat(cfg.ManagedVolumeDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe store modified before rejection: %v", err)
			}
		})
	}
}
