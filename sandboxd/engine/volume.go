package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cocoonstack/sandbox/protocol/wire"
	"github.com/cocoonstack/sandbox/sandboxd/types"
)

const (
	// VolumeCallTimeout bounds one guest teardown exec.
	VolumeCallTimeout = 2 * time.Second

	volumePollInterval = 10 * time.Millisecond
	volumeProbeTimeout = 2 * time.Second
	volumeSetupTimeout = 10 * time.Second
)

// VolumeSpec describes one operator-owned disk image attached to a sandbox.
type VolumeSpec struct {
	Name     string
	Path     string
	DirectIO string
	RW       bool
}

func (s VolumeSpec) directIO() (string, error) {
	mode := cmp.Or(s.DirectIO, types.DirectIOOff)
	if !types.ValidDirectIO(mode) {
		return "", fmt.Errorf("volume directio must be on, off, or auto, got %q", s.DirectIO)
	}
	return mode, nil
}

// DiskAttach hot-attaches an operator-owned disk through cocoon.
func (e *Engine) DiskAttach(ctx context.Context, vmName string, spec VolumeSpec) error {
	args, err := e.diskAttachArgs(vmName, spec)
	if err != nil {
		return err
	}
	_, err = e.run(ctx, args...)
	return err
}

// MountVolume discovers and mounts a hot-attached disk at mount, read-only unless rw.
func (e *Engine) MountVolume(ctx context.Context, vsockSocket, name, mount string, rw bool) error {
	ctx, cancel := context.WithTimeout(ctx, volumeSetupTimeout)
	defer cancel()
	device, err := e.waitForVolumeDevice(ctx, vsockSocket, name)
	if err != nil {
		return fmt.Errorf("wait for volume device %s: %w", name, err)
	}
	if err := e.silkdExec(ctx, vsockSocket, "mkdir", "-p", "--", mount); err != nil {
		return fmt.Errorf("create volume mount point %s: %w", mount, err)
	}
	mode := types.VolumeModeRO
	if rw {
		mode = types.VolumeModeRW
	}
	if err := e.silkdExec(ctx, vsockSocket, "mount", "-o", mode, "--", device, mount); err != nil {
		return fmt.Errorf("mount volume %s: %w", name, err)
	}
	return nil
}

// UnmountVolume flushes and detaches a guest mount before the VM is removed.
func (e *Engine) UnmountVolume(ctx context.Context, vsockSocket, mount string) error {
	ctx, cancel := context.WithTimeout(ctx, VolumeCallTimeout)
	defer cancel()
	if err := e.silkdExec(ctx, vsockSocket, "umount", "--", mount); err != nil {
		return fmt.Errorf("unmount volume %s: %w", mount, err)
	}
	return nil
}

// SyncGuest flushes the guest page cache, the only flush left for a failed unmount.
func (e *Engine) SyncGuest(ctx context.Context, vsockSocket string) error {
	ctx, cancel := context.WithTimeout(ctx, VolumeCallTimeout)
	defer cancel()
	if err := e.silkdExec(ctx, vsockSocket, "sync"); err != nil {
		return fmt.Errorf("sync guest: %w", err)
	}
	return nil
}

// DiskDetach hot-detaches an operator-owned disk by its serial name.
func (e *Engine) DiskDetach(ctx context.Context, vmName, name string) error {
	_, err := e.run(ctx, "vm", "disk", "detach", vmName, argName, name)
	return err
}

// AttachVolume converges a disk and its guest mount. It is safe to
// retry after a daemon crash between the host operation and claim persistence.
func (e *Engine) AttachVolume(
	ctx context.Context,
	vmName, vsockSocket string,
	spec VolumeSpec,
	mount string,
) error {
	_, found, err := e.findVolumeDevice(ctx, vsockSocket, spec.Name)
	if err != nil {
		return err
	}
	attached := false
	if !found {
		if err := e.DiskAttach(ctx, vmName, spec); err != nil {
			return err
		}
		attached = true
	}
	if err := e.silkdExec(ctx, vsockSocket, "mountpoint", "-q", "--", mount); err == nil {
		return nil
	}
	if err := e.MountVolume(ctx, vsockSocket, spec.Name, mount, spec.RW); err != nil {
		if attached {
			_ = e.DiskDetach(context.WithoutCancel(ctx), vmName, spec.Name)
		}
		return err
	}
	return nil
}

// DetachVolume converges a guest unmount and host hot-unplug. A missing serial
// means a prior attempt completed the physical operation.
func (e *Engine) DetachVolume(
	ctx context.Context,
	vmName, vsockSocket, name, mount string,
) error {
	_, found, err := e.findVolumeDevice(ctx, vsockSocket, name)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if err := e.silkdExec(ctx, vsockSocket, "mountpoint", "-q", "--", mount); err == nil {
		if err := e.UnmountVolume(ctx, vsockSocket, mount); err != nil {
			return err
		}
	}
	return e.DiskDetach(ctx, vmName, name)
}

func (e *Engine) waitForVolumeDevice(ctx context.Context, vsockSocket, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, volumeProbeTimeout)
	defer cancel()
	ticker := time.NewTicker(volumePollInterval)
	defer ticker.Stop()
	for {
		device, found, err := e.findVolumeDevice(ctx, vsockSocket, name)
		if err != nil {
			return "", cmp.Or(ctx.Err(), err)
		}
		if found {
			return device, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *Engine) findVolumeDevice(ctx context.Context, vsockSocket, name string) (string, bool, error) {
	entries, err := e.silkdList(ctx, vsockSocket, "/sys/block")
	if err != nil {
		return "", false, err
	}
	for _, entry := range entries {
		serial, err := e.silkdReadFile(ctx, vsockSocket, "/sys/block/"+entry.Name+"/serial")
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		if strings.TrimSpace(string(serial)) != name {
			continue
		}
		device := "/dev/" + entry.Name
		// The kernel publishes /sys/block before devtmpfs creates the node.
		if err := e.silkdStat(ctx, vsockSocket, device); err != nil {
			if isNotFound(err) {
				return "", false, nil
			}
			return "", false, err
		}
		return device, true, nil
	}
	return "", false, nil
}

func (e *Engine) diskAttachArgs(vmName string, spec VolumeSpec) ([]string, error) {
	directIO, err := spec.directIO()
	if err != nil {
		return nil, err
	}
	args := []string{
		"vm", "disk", "attach", vmName,
		"--path", spec.Path,
		argName, spec.Name,
	}
	if !spec.RW {
		args = append(args, "--readonly")
	}
	return append(args, "--directio", directIO), nil
}

func isNotFound(err error) bool {
	var respErr *wire.ErrorResp
	return errors.As(err, &respErr) && respErr.Kind == wire.KindNotFound
}
