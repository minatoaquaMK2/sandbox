# Managed-volume recovery verification, 2026-10-19

The current sandbox repository passed all fifteen real-runtime cases after the
second review's recovery and storage-layout fixes. This record supersedes the
older binary qualification for these behaviors. The older
[twelve-case record](managed-volumes-2026-10-19.md) remains historical evidence.

- Qualified source and driver `64e88662893de5f919e46e45871e7c13f75e8f50`.
- Binary SHA-256 `e5fbcc8022c24f120f5b0edbb1c5002e90a3d1a04c965ccb44af047dff4c1793`.
- Verification attempt `7f094dff5ebacc26022839a72056cdf0`.
- Go VCS metadata reports the qualified source and `vcs.modified=false`.
- [Machine-readable results and raw artifact digests](managed-volume-recovery-2026-10-19.json).

The binary was built in a clean detached checkout. The verifier checked the
source, tracked cleanliness, SDK digest, fixture hashes, on-disk binary and
running executable at case boundaries. All fifteen receipts share the same
source, binary and attempt. Later documentation commits do not change this pin.
After qualification, Ruff reflowed one fixture assertion. Its parsed Python AST
is identical to the qualified fixture; the receipt hashes still describe the
original `64e8866` source. No Go production file changed after qualification.

## Fixed behavior and evidence

| Finding | Result | Evidence |
| --- | --- | --- |
| R1. Quarantine removal retry disappeared after restart when registry retirement was not published | The exact persisted quarantine reason resumes retirement and removal. Ordinary failure reasons retain ownership. | MV-14 and the async/sync, pre-/post-publication source regression matrix. |
| R2. Dead unclaimed VM records blocked startup when a managed resource existed | Confirmed dead untracked records are removed and freshly inspected before startup continues. Unknown metadata, running PID zero and ineffective removal still block startup. | MV-13 plus process-uncertainty, stale-create and tracked-generation source controls. |
| H1. Accepted storage layouts could be swept on startup | Configuration rejects stores in cleanup trees and stable symbolic-link overlaps before daemon files are created. | MV-15, path/alias controls and backing-preservation regression tests. |

The independent source reviewer found an additional inverse alias during this
fix round. A `readers` or `goldens` link into `managed/disks` passed the first
check and let cleanup erase real temporary backing files. Commit `4ef0624`
records the failing tests before `310cb2d` adds the narrow backing-directory
guard. The same-root and benign ancestor-placement controls still pass.

The initial regressions landed in `1e9a776` before production changes.
Additional alias tests landed before their fixes. Retained
[red results](managed-volume-recovery-2026-10-19/checks/red.txt) and
[inverse-alias backing loss](managed-volume-recovery-2026-10-19/checks/inverse-alias-red.txt)
show the original failures. The
[final sandboxd race log](managed-volume-recovery-2026-10-19/checks/sandboxd-race-final.txt)
records the green combined implementation.

## Real VM and persistent-storage proof

MV-01 through MV-12 reran the existing lifecycle, auth, concurrency, native
catalog cancellation and storage cases. MV-08 now retains both raw PID/start
identities for fresh claims under each `sync_claims` setting, so the comparison
can be recomputed from the receipt.

MV-13 starts an owned unclaimed VM, records its running process, then stops it.
Cocoon reports the same VM as stopped with PID zero. A managed resource exists
throughout. Restart becomes ready, removes that exact stale record and retains
the resource identity.

MV-14 seeds only two owned claim-journal failure fields while sandboxd is
stopped. The managed registry stays byte-identical with claimed holds. A wrapper
refuses removal of the exact quarantined VM. After restart, its actual VMM
PID/start remains alive, and managed writer admission and deletion return 409.
An ordinary failed managed claim remains alive and claimed as a control. After
the wrapper refusal is removed, retry removes the quarantined VMM, frees its
hold and lets template B read the original filesystem UUID and payload hash.
This case seeds a recovery state and injects a runtime command refusal. It does
not inject a firewall failure or a registry fsync failure. The source fault
matrix covers registry publication failures with a fake engine.

MV-15 invokes the exact qualified binary against six disposable unsafe layouts
and two cleanup-to-backing symbolic links. All eight invocations exit one at
configuration validation. The six new paths remain absent; the two pre-existing
backing markers remain unchanged and no registry appears. The actual managed
registry/backing and guest UUID/payload remain intact. Nested disposable config
files contain ephemeral tokens and are excluded from published raw artifacts.

The managed resource was a sparse 20 GiB disk on an exclusively owned 12 GiB
ext4 loop filesystem backed by a file on host ext4/LVM. The
[host observations](managed-volume-recovery-2026-10-19/host-storage.json)
record that storage chain. Cocoon 0.7.3, Cloud Hypervisor 54 and guest kernel
6.18.37 use the same official sandbox base layers as the earlier record.

- Resource ID `vol_0edc22a5337522d69c392bc102dde41c`.
- Backing device/inode `1798/524356` and size `21474836480` bytes.
- Guest filesystem UUID `e67f1c44-13ba-4497-b393-7c709367b443`.
- Payload SHA-256 `b0b7a13acdfe3a9bd68b04b54862a888712f44f60df4ea6def18a37c9143bf87`, covering 4,194,304 bytes.

MV-12 stops owned services, normally unmounts the outer filesystem, observes
mount absence, flushes loop buffers and runs read-only `e2fsck -f -n` with exit
zero. It remounts the same outer UUID and verifies the same resource ID, backing
identity, guest UUID and bytes. This is persistent host-file-backed storage
proof, not host reboot, abrupt power loss or a bare NVMe namespace test.

## Review and checks

The [independent source review](managed-volume-recovery-2026-10-19/checks/independent-source-review.md)
passes at the qualified pin. A separate nonauthor
[proof-method review](managed-volume-recovery-2026-10-19/checks/independent-proof-review.md)
accepts the driver and aggregation controls. The
[runtime receipt audit](managed-volume-recovery-2026-10-19/checks/independent-runtime-review.md)
checks the actual final results. Reviewer reuse was required by agent capacity;
these are separate responsibilities, not a claim of model diversity.

Race-enabled suites passed in sandboxd, sdk/go, e2e, mcp and protocol/wire.
Sandboxd permission tests ran with DAC override capabilities dropped. All 279
Python SDK tests, strict mypy, Ruff and the sandboxd Darwin build passed.
The comment audit found no introduced comments or suppressions requiring edits.

`make go-lint` remains blocked by pinned golangci-lint 2.13.2 being unable to
read Go 1.27 export-data version 5. The
[tool failure](managed-volume-recovery-2026-10-19/checks/go-lint.txt)
begins in unchanged protocol/wire imports. No lint pass is claimed.

## Limits and cleanup

The R1 regression waits for the asynchronous quarantine marker to reach the
claim journal. A crash before that marker write is not directly injected; the
prior active journal must pass the existing egress relock or quarantine path.
Stable symbolic-link validation does not detect bind-mount aliases or prevent
concurrent trusted-host pathname swaps. No host power-loss, ENOSPC, hibernate,
growth, placement or archive qualification is claimed.

An earlier live trial passed MV-01 through MV-10, then caught the fixture's
incorrect assumption that stopped Cocoon records retain an API socket. That
trial was cleaned up and does not contribute to the final fifteen-case count.
The final attempt rebuilt the corrected driver and binary from one clean pin.

The [cleanup receipt](managed-volume-recovery-2026-10-19/cleanup.json) records
zero owned claims, managed resources, holds, backing files and VMs. The owned
mount is absent and its loop association is detached. Six pre-existing foreign
processes retain their PID/start identities. The private filesystem image and
private evidence copy remain available for inspection.

Use the [existing isolated rerun instructions](managed-volumes-2026-10-19.md#rerun).
The current driver requires MV-01 through MV-15 from one attempt. Run `verify`,
then `storage`, then `report` and `cleanup`. Never target a shared runtime.
