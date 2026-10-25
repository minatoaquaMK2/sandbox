package e2e

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/config"
	"github.com/cocoonstack/sandbox/sandboxd/tenants"
	sandbox "github.com/cocoonstack/sandbox/sdk/go"
)

func TestRuntimeVolumePublicAdmissionThroughHTTP(t *testing.T) {
	st := startTenantStack(t, "node-token", []tenants.TenantSpec{{Name: "acme", Token: "acme-token"}}, nil)
	acme, err := sandbox.Connect(st.addr, sandbox.WithAPIToken("acme-token"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(map[string]any{"path": writeVolumeImage(t, "home.img", "shared bytes"), "writable": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct {
		token string
		want  int
	}{{"acme-token", http.StatusForbidden}, {"", http.StatusUnauthorized}, {"node-token", http.StatusNoContent}} {
		caller := *st
		caller.token = scope.token
		if status, body := rawJSON(t, &caller, http.MethodPut, "/v1/volumes/home", string(request)); status != scope.want {
			t.Fatalf("registration auth: status=%d want=%d body=%s", status, scope.want, body)
		}
	}
	volumes, err := acme.Volumes(t.Context())
	if err != nil || len(volumes) != 1 || volumes[0].Name != "home" {
		t.Fatalf("empty runtime ACL is public: volumes=%v err=%v", volumes, err)
	}
	volume := sandbox.Volume{Name: "home", Mode: "rw", AttachOnly: true}
	first, err := acme.New(t.Context(), "rt:24.04", sandbox.WithVolumes(volume))
	if err != nil {
		t.Fatalf("tenant claim with public runtime volume: %v", err)
	}
	defer first.Close()
	if !slices.Equal(first.Volumes, []sandbox.Volume{volume}) {
		t.Fatalf("claim did not retain explicit attach_only: %+v", first.Volumes)
	}
	if _, err = first.SetVolumes(t.Context(), []sandbox.Volume{}); err != nil {
		t.Fatal(err)
	}
	if view, attachErr := first.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{volume}}); attachErr != nil || !slices.Equal(view.Volumes, []sandbox.Volume{volume}) {
		t.Fatalf("tenant PATCH of public runtime volume: view=%+v err=%v", view, attachErr)
	}
	if _, err = first.SetVolumes(t.Context(), []sandbox.Volume{}); err != nil {
		t.Fatal(err)
	}
	if view, attachErr := first.SetVolumes(t.Context(), []sandbox.Volume{volume}); attachErr != nil || !slices.Equal(view.Volumes, []sandbox.Volume{volume}) {
		t.Fatalf("tenant PUT of public runtime volume: view=%+v err=%v", view, attachErr)
	}
}

func TestRuntimeVolumeExplicitACLAndStaticPublicThroughHTTP(t *testing.T) {
	st := startTenantStack(t, "node-token", []tenants.TenantSpec{
		{Name: "acme", Token: "acme-token"}, {Name: "beta", Token: "beta-token"},
	}, []config.VolumeSpec{{Name: "public", Path: writeVolumeImage(t, "public.img", "shared")}})
	request, err := json.Marshal(map[string]any{"path": writeVolumeImage(t, "private.img", "private"), "tenants": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := rawJSON(t, st, http.MethodPut, "/v1/volumes/private", string(request)); status != http.StatusNoContent {
		t.Fatalf("registration: %d %s", status, body)
	}
	for _, tc := range []struct {
		token string
		want  []string
	}{{"acme-token", []string{"private", "public"}}, {"beta-token", []string{"public"}}} {
		client, connectErr := sandbox.Connect(st.addr, sandbox.WithAPIToken(tc.token))
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		volumes, listErr := client.Volumes(t.Context())
		var names []string
		for _, volume := range volumes {
			names = append(names, volume.Name)
		}
		if listErr != nil || !slices.Equal(names, tc.want) {
			t.Fatalf("catalog ACL: names=%v want=%v err=%v", names, tc.want, listErr)
		}
		claim, claimErr := client.New(t.Context(), "rt:24.04", sandbox.WithVolumes(sandbox.Volume{Name: "public"}))
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		defer claim.Close()
		_, attachErr := claim.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{{Name: "private"}}})
		if (attachErr == nil) != (tc.token == "acme-token") {
			t.Fatalf("explicit ACL admission for %s: %v", tc.token, attachErr)
		}
		if tc.token == "beta-token" {
			caller := *st
			caller.token = tc.token
			var forbidden []byte
			for _, name := range []string{"private", "unknown"} {
				status, body := rawJSON(t, &caller, http.MethodPost, "/v1/claim", `{"template":"rt:24.04","volumes":[{"name":"`+name+`"}]}`)
				if status != http.StatusBadRequest {
					t.Fatalf("claim privacy for %s: status=%d body=%s", name, status, body)
				}
				if name == "private" {
					forbidden = body
				} else if string(body) != string(forbidden) {
					t.Fatalf("forbidden and unknown responses differ: %s versus %s", forbidden, body)
				}
			}
		}
	}
}

func TestRuntimeVolumeDetachHibernateWakeThroughHTTP(t *testing.T) {
	st := startTenantStack(t, "node-token", []tenants.TenantSpec{{Name: "acme", Token: "acme-token"}}, nil)
	request, err := json.Marshal(map[string]any{"path": writeVolumeImage(t, "home.img", "external bytes"), "writable": true, "tenants": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := rawJSON(t, st, http.MethodPut, "/v1/volumes/home", string(request)); status != http.StatusNoContent {
		t.Fatalf("registration: %d %s", status, body)
	}
	acme, err := sandbox.Connect(st.addr, sandbox.WithAPIToken("acme-token"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := acme.New(t.Context(), "rt:24.04")
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Close()
	other, err := acme.New(t.Context(), "rt:24.04")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	operator := st.client.Attach(st.addr, claim.ID, "")
	otherOperator := st.client.Attach(st.addr, other.ID, "")
	volume := sandbox.Volume{Name: "home", Mode: "rw", AttachOnly: true}
	if _, err = operator.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{volume}}); err != nil {
		t.Fatal(err)
	}
	if err = claim.Hibernate(t.Context()); err == nil {
		t.Fatal("captured an attached disk")
	} else if refusal, ok := errors.AsType[*sandbox.APIError](err); !ok || refusal.Status != http.StatusConflict {
		t.Fatalf("attached capture refusal: %v", err)
	}
	if _, err = otherOperator.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{volume}}); err == nil {
		t.Fatal("root admitted a second writer before detach")
	} else if refusal, ok := errors.AsType[*sandbox.APIError](err); !ok || refusal.Status != http.StatusConflict {
		t.Fatalf("second writer refusal: %v", err)
	}
	view, err := operator.PatchVolumes(t.Context(), sandbox.VolumePatch{Remove: []string{"home"}})
	if err != nil || len(view.Volumes) != 0 || len(view.VolumesWant) != 0 || len(view.States) != 0 || view.Converging {
		t.Fatalf("detach acknowledgment: %+v %v", view, err)
	}
	if err = claim.Hibernate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !hibernated(t, st, claim.ID) {
		t.Fatal("detach followed by hibernate did not sleep the claim")
	}
	registered, listErr := st.client.Volumes(t.Context())
	if listErr != nil || len(registered) != 1 || registered[0].Name != "home" || !registered[0].Writable {
		t.Fatalf("registration lost across sleep: %+v %v", registered, listErr)
	}
	if _, err = other.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{volume}}); err != nil {
		t.Fatalf("detached volume stayed reserved during sleep: %v", err)
	}
	if _, err = otherOperator.PatchVolumes(t.Context(), sandbox.VolumePatch{Remove: []string{"home"}}); err != nil {
		t.Fatal(err)
	}
	beforeWake := st.eng.volumeOpsLog()
	if out, execErr := claim.Exec(t.Context(), "echo", "awake"); execErr != nil || out != "awake\n" {
		t.Fatalf("implicit wake: %q %v", out, execErr)
	}
	if hibernated(t, st, claim.ID) {
		t.Fatal("guest request did not wake the original claim")
	}
	if ops := st.eng.volumeOpsLog(); !slices.Equal(ops, beforeWake) {
		t.Fatalf("wake unexpectedly operated on external disks: %v -> %v", beforeWake, ops)
	}
	view, err = claim.GetVolumes(t.Context())
	if err != nil || len(view.Volumes) != 0 || len(view.VolumesWant) != 0 || len(view.States) != 0 || view.Converging {
		t.Fatalf("wake unexpectedly restored volume references: %+v %v", view, err)
	}
	view, err = operator.PatchVolumes(t.Context(), sandbox.VolumePatch{Add: []sandbox.Volume{volume}})
	if err != nil || !slices.Equal(view.Volumes, []sandbox.Volume{volume}) || view.Converging {
		t.Fatalf("controller reattachment: %+v %v", view, err)
	}
	if status, body := rawJSON(t, st, http.MethodDelete, "/v1/volumes/home", ""); status != http.StatusConflict {
		t.Fatalf("unregister attached restored disk: %d %s", status, body)
	}
}
