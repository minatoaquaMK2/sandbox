package pool

import (
	"path/filepath"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestDetachingOwnersTracksAnUndurableDetach(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		t.Run(map[bool]string{false: "attempted-only", true: "acknowledged"}[acknowledged], func(t *testing.T) {
			s := newClaimStore(t.TempDir(), false)
			sb := &types.Sandbox{ID: "owner", Volumes: []types.Volume{{Name: "data"}}}
			if acknowledged {
				if err := s.commit(s.set(sb)); err != nil {
					t.Fatal(err)
				}
			}
			restore := failClaimWrites(t, s)
			if err := s.commit(s.set(sb)); err == nil {
				t.Fatal("expected failed attachment snapshot")
			}
			if got := s.detachingOwners(); len(got) != 0 {
				t.Fatalf("current attachment counted as detaching: %v", got)
			}
			sb.Volumes = nil
			s.set(sb)
			if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] {
				t.Fatalf("memory detach lost retained attachment: %v", got)
			}
			if err := s.commit(s.mark()); err == nil {
				t.Fatal("expected failed detach snapshot")
			}
			if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] {
				t.Fatalf("failed detach lost retained attachment: %v", got)
			}
			sb.VolumesWant = []types.Volume{{Name: "data"}}
			s.set(sb)
			if got := s.detachingOwners(); len(got) != 0 {
				t.Fatalf("desired reattachment counted as detaching: %v", got)
			}
			sb.VolumesWant = nil
			s.set(sb)
			restore()
			if err := s.commit(s.mark()); err != nil {
				t.Fatal(err)
			}
			if got := s.detachingOwners(); len(got) != 0 || s.hasRecoveryVolumes(sb.ID) {
				t.Fatalf("acknowledged detach retained attachment: %v", got)
			}
		})
	}
}

func TestDetachingOwnersSurvivesLoadAndReset(t *testing.T) {
	s := newClaimStore(t.TempDir(), false)
	sb := &types.Sandbox{ID: "owner", Volumes: []types.Volume{{Name: "data"}}}
	if err := s.commit(s.set(sb)); err != nil {
		t.Fatal(err)
	}
	s = newClaimStore(filepath.Dir(s.path), false)
	claims, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] {
		t.Fatalf("loaded attachment missing before current rows reset: %v", got)
	}
	s.reset(claims)
	if got := s.detachingOwners(); len(got) != 0 {
		t.Fatalf("loaded current attachment counted as detaching: %v", got)
	}
	s.reset(map[string]*types.Sandbox{})
	if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] {
		t.Fatalf("startup filtering lost retained attachment: %v", got)
	}
	if err := s.commit(s.mark()); err != nil {
		t.Fatal(err)
	}
	if got := s.detachingOwners(); len(got) != 0 {
		t.Fatalf("acknowledged reset retained attachment: %v", got)
	}
}

func TestDetachingOwnersAcknowledgesCapturedRowsBeforeNewerReplacement(t *testing.T) {
	s := newClaimStore(t.TempDir(), false)
	sb := &types.Sandbox{ID: "owner", Volumes: []types.Volume{{Name: "data"}}}
	release := captureClaimWrite(t, s, s.set(sb), sb.ID)
	sb.Volumes = nil
	newer := s.set(sb)
	if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] {
		t.Fatalf("in-flight captured attachment missing: %v", got)
	}
	release()
	if got := s.detachingOwners(); len(got) != 1 || !got[sb.ID] || !s.pending(newer) {
		t.Fatalf("older acknowledgment retired newer detach: %v", got)
	}
	if err := s.commit(newer); err != nil {
		t.Fatal(err)
	}
	if got := s.detachingOwners(); len(got) != 0 {
		t.Fatalf("newer acknowledgment retained attachment: %v", got)
	}
}
