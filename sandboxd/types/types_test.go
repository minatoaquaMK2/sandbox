package types

import "testing"

func TestValidateSizes(t *testing.T) {
	for _, tt := range []struct {
		size Size
		ok   bool
	}{
		{SizeSmall, true},
		{SizeMedium, true},
		{SizeLarge, true},
		{SizeXLarge, true},
		{Size("huge"), false},
		{Size(""), false},
	} {
		t.Run(string(tt.size), func(t *testing.T) {
			err := PoolKey{Template: "rt:24.04", Net: NetNone, Size: tt.size}.Validate()
			if (err == nil) != tt.ok {
				t.Errorf("Validate: %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestXLargeSpec(t *testing.T) {
	spec, ok := SizeXLarge.Spec()
	if !ok || spec.CPU != 4 || spec.Memory != "8G" {
		t.Errorf("got %+v ok=%v, want {4 8G} true", spec, ok)
	}
}

func TestPoolKeyHashPreservesCloudHypervisorDiscriminator(t *testing.T) {
	key := PoolKey{Template: "aiops-agent-private-v2", Net: NetNone, Size: SizeXLarge}
	const want = "d2e47ddd697f726119d1d16849c27566"
	if got := key.Hash(); got != want {
		t.Fatalf("Hash() = %q, want persisted pre-v0.1.8 hash %q", got, want)
	}
}
