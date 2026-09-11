package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/cocoonstack/sandbox/sandboxd/types"
)

func TestVolumeMutationEndpointsUseSandboxToken(t *testing.T) {
	want := []types.Volume{{Name: "kb-0123456789abcdef", Mount: "/agent-context/bases/wiki"}}
	var gotToken string
	mgr := &fakeManager{
		attachVolumes: func(id, token string, volumes []types.Volume) ([]types.Volume, error) {
			if id != "sb_1" {
				t.Errorf("id=%q", id)
			}
			gotToken = token
			if !slices.Equal(volumes, want) {
				t.Errorf("volumes=%v", volumes)
			}
			return want, nil
		},
		detachVolumes: func(id, token string, names []string) ([]types.Volume, error) {
			gotToken = token
			if id != "sb_1" || !slices.Equal(names, []string{want[0].Name}) {
				t.Errorf("detach id=%q names=%v", id, names)
			}
			return nil, nil
		},
	}
	ts := newTestServer(t, "root-token", mgr, nil)
	post := func(path string, body any, token string) *http.Response {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, _ := http.NewRequestWithContext(
			context.Background(), http.MethodPost, ts.URL+path, bytes.NewReader(raw),
		)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := post("/v1/sandboxes/sb_1/volumes/attach", types.VolumeAttachRequest{Volumes: want}, "sandbox-token")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || gotToken != "sandbox-token" {
		t.Fatalf("attach status=%d token=%q", response.StatusCode, gotToken)
	}
	var attached types.VolumeMutationResponse
	if err := json.NewDecoder(response.Body).Decode(&attached); err != nil || !slices.Equal(attached.Volumes, want) {
		t.Fatalf("attach response=%v err=%v", attached, err)
	}

	response = post("/v1/sandboxes/sb_1/volumes/detach", types.VolumeDetachRequest{Names: []string{want[0].Name}}, "sandbox-token")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || gotToken != "sandbox-token" {
		t.Fatalf("detach status=%d token=%q", response.StatusCode, gotToken)
	}

	request, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		ts.URL+"/v1/sandboxes/sb_1/volumes/attach", bytes.NewReader([]byte(`{"volumes":[]}`)),
	)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", response.StatusCode)
	}
}
