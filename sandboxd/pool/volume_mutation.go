package pool

import (
	"context"
	"fmt"
	"slices"

	"github.com/cocoonstack/sandbox/sandboxd/engine"
	"github.com/cocoonstack/sandbox/sandboxd/types"
)

// AttachVolumes adds read-only volumes to a running claim. Repeating an
// identical request is a no-op.
func (m *Manager) AttachVolumes(
	ctx context.Context,
	id string,
	cred Cred,
	requested []types.Volume,
) ([]types.Volume, error) {
	requested, err := types.ValidateVolumes(requested, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadVolume, err)
	}
	if slices.ContainsFunc(requested, types.Volume.RW) {
		return nil, fmt.Errorf("%w: live volume attach is read-only", ErrBadVolume)
	}
	sb, ok := m.resolve(id, cred)
	if !ok {
		return nil, ErrUnknownSandbox
	}
	sb.Transition.Lock()
	defer sb.Transition.Unlock()

	current, err := m.mutableVolumeState(id, sb)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]types.Volume, len(current))
	for _, volume := range current {
		byName[volume.Name] = volume
	}
	combined := slices.Clone(current)
	toAdd := make([]types.Volume, 0, len(requested))
	for _, volume := range requested {
		if existing, exists := byName[volume.Name]; exists {
			if existing.Mount != volume.Mount {
				return nil, fmt.Errorf("%w: volume %q is already mounted at %q", ErrBadVolume, volume.Name, existing.Mount)
			}
			continue
		}
		combined = append(combined, volume)
		toAdd = append(toAdd, volume)
		byName[volume.Name] = volume
	}
	combined, err = types.ValidateVolumes(combined, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadVolume, err)
	}
	if len(toAdd) == 0 {
		return combined, nil
	}
	resolved, err := m.resolveVolumes(ctx, sb.Tenant, toAdd)
	if err != nil {
		return nil, err
	}
	reserved, err := m.reserveLiveVolumes(id, sb, resolved)
	if err != nil {
		return nil, err
	}
	keepReservation := false
	defer func() {
		if !keepReservation {
			m.unreserveVolumes(reserved)
		}
	}()
	applied := make([]resolvedVolume, 0, len(resolved))
	for _, volume := range resolved {
		if err := m.eng.AttachVolume(
			ctx, sb.VMName, sb.VsockSocket, volume.disk, volume.applied.Mount,
		); err != nil {
			m.rollbackAttachedVolumes(ctx, sb, applied)
			return nil, fmt.Errorf("attach volume %q: %w", volume.applied.Name, err)
		}
		applied = append(applied, volume)
	}
	if err := m.commitVolumeMutation(ctx, id, sb, current, combined); err != nil {
		m.rollbackAttachedVolumes(ctx, sb, applied)
		return nil, err
	}
	keepReservation = true
	m.recordUsage(ctx, usageEvent{
		Event: "volume_attach", ID: sb.ID, VMName: sb.VMName,
		Tenant: sb.Tenant, Volumes: types.VolumeNames(toAdd),
	})
	return combined, nil
}

// DetachVolumes removes named volumes from a running claim. Names that are
// already absent make retries succeed.
func (m *Manager) DetachVolumes(
	ctx context.Context,
	id string,
	cred Cred,
	names []string,
) ([]types.Volume, error) {
	if len(names) > types.MaxClaimVolumes {
		return nil, fmt.Errorf("%w: too many volume names", ErrBadVolume)
	}
	requested := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !types.ValidVolumeName(name) {
			return nil, fmt.Errorf("%w: invalid volume name %q", ErrBadVolume, name)
		}
		if _, exists := requested[name]; exists {
			return nil, fmt.Errorf("%w: duplicate volume name %q", ErrBadVolume, name)
		}
		requested[name] = struct{}{}
	}
	sb, ok := m.resolve(id, cred)
	if !ok {
		return nil, ErrUnknownSandbox
	}
	sb.Transition.Lock()
	defer sb.Transition.Unlock()

	current, err := m.mutableVolumeState(id, sb)
	if err != nil {
		return nil, err
	}
	remaining := make([]types.Volume, 0, len(current))
	removed := make([]resolvedVolume, 0, len(names))
	for _, volume := range current {
		if _, remove := requested[volume.Name]; !remove {
			remaining = append(remaining, volume)
			continue
		}
		if volume.RW() {
			return nil, fmt.Errorf("%w: live detach of writable volume %q is not supported", ErrBadVolume, volume.Name)
		}
		entry, _, _ := m.lookupVolume(volume.Name)
		if entry.disk.Name == "" {
			entry.disk = engine.VolumeSpec{Name: volume.Name}
		}
		removed = append(removed, resolvedVolume{disk: entry.disk, applied: volume})
	}
	if len(removed) == 0 {
		return remaining, nil
	}
	detached := make([]resolvedVolume, 0, len(removed))
	for _, volume := range slices.Backward(removed) {
		if err := m.eng.DetachVolume(
			ctx, sb.VMName, sb.VsockSocket, volume.applied.Name, volume.applied.Mount,
		); err != nil {
			m.rollbackDetachedVolumes(ctx, sb, detached)
			return nil, fmt.Errorf("detach volume %q: %w", volume.applied.Name, err)
		}
		detached = append(detached, volume)
	}
	if err := m.commitVolumeMutation(ctx, id, sb, current, remaining); err != nil {
		m.rollbackDetachedVolumes(ctx, sb, detached)
		return nil, err
	}
	m.unreserveVolumes(appliedVolumes(removed))
	m.recordUsage(ctx, usageEvent{
		Event: "volume_detach", ID: sb.ID, VMName: sb.VMName,
		Tenant: sb.Tenant, Volumes: names,
	})
	return remaining, nil
}

func (m *Manager) mutableVolumeState(id string, sb *types.Sandbox) ([]types.Volume, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimed[id] != sb {
		return nil, ErrUnknownSandbox
	}
	if sb.HibernateSnap != "" || sb.PendingSnap != "" ||
		sb.ArchiveCk != "" || sb.VsockSocket == "" {
		return nil, ErrVolumeState
	}
	return slices.Clone(sb.Volumes), nil
}

func (m *Manager) reserveLiveVolumes(id string, sb *types.Sandbox, volumes []resolvedVolume) ([]types.Volume, error) {
	applied := appliedVolumes(volumes)
	m.mu.Lock()
	if m.claimed[id] != sb {
		m.mu.Unlock()
		return nil, ErrUnknownSandbox
	}
	err := m.reserveVolumes(applied)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := m.confirmVolumesClean(volumes); err != nil {
		m.unreserveVolumes(applied)
		return nil, err
	}
	return applied, nil
}

func (m *Manager) commitVolumeMutation(
	ctx context.Context,
	id string,
	sb *types.Sandbox,
	previous, next []types.Volume,
) error {
	m.mu.Lock()
	if m.claimed[id] != sb {
		m.mu.Unlock()
		return ErrUnknownSandbox
	}
	sb.Volumes = slices.Clone(next)
	snapshot := m.store.set(sb)
	m.mu.Unlock()
	if err := m.store.commit(snapshot); err != nil {
		m.mu.Lock()
		if m.claimed[id] == sb && slices.Equal(sb.Volumes, next) {
			sb.Volumes = slices.Clone(previous)
			rollback := m.store.set(sb)
			m.mu.Unlock()
			m.recommit(ctx, rollback)
		} else {
			m.mu.Unlock()
		}
		return fmt.Errorf("persist sandbox volumes: %w", err)
	}
	sb.Touch()
	return nil
}

func (m *Manager) rollbackAttachedVolumes(
	ctx context.Context,
	sb *types.Sandbox,
	volumes []resolvedVolume,
) {
	ctx = context.WithoutCancel(ctx)
	for _, volume := range slices.Backward(volumes) {
		_ = m.eng.DetachVolume(
			ctx, sb.VMName, sb.VsockSocket, volume.applied.Name, volume.applied.Mount,
		)
	}
}

func (m *Manager) rollbackDetachedVolumes(
	ctx context.Context,
	sb *types.Sandbox,
	volumes []resolvedVolume,
) {
	ctx = context.WithoutCancel(ctx)
	for _, volume := range slices.Backward(volumes) {
		if volume.disk.Path == "" {
			continue
		}
		_ = m.eng.AttachVolume(
			ctx, sb.VMName, sb.VsockSocket, volume.disk, volume.applied.Mount,
		)
	}
}
