# Managed-volume verification, 2026-10-19

The current **sandbox** repository passed twelve real-runtime cases on one
clean binary. The [feature map](../managed-volumes.md#feature-map) separates
these cases from source fixtures and deferred scope.

- Source and driver `48324c1f7810bf8eb626f4e461d61a271314a135`.
- Binary SHA-256 `dcb2bc8221b031e2fd109100d1c54690e5b9b43c49509ca6ac44d6bd0bbe810d`.
- Go VCS metadata reports that source and `vcs.modified=false`.
- Attempt `f40bfe8e5f31b552fcf87e9f38522fb8`.
- [Machine-readable report and artifact digests](managed-volumes-2026-10-19.json).

The binary was built in a clean detached worktree. The verifier checked the
module path, current source, tracked cleanliness, SDK digest, fixture hashes,
on-disk binary hash and running executable hash. It checked the binding at
case boundaries and refused to aggregate receipts with different provenance.
Later documentation commits do not change the qualified binary pin.
Redacted [raw results, HTTP and guest traces, and storage commands](managed-volumes-2026-10-19/) are retained alongside the digest index.

## Observed environment

Cocoon v0.7.3, Cloud Hypervisor v54.0.0 and guest kernel 6.18.37 ran on Linux
7.0.0-38-generic with KVM. The guest came from official sandbox base layers,
OCI manifest `sha256:d6b6b39a4984fa0e6cf9c7fa9a1aadbc5708085146f52923c6137015f4a4e843`.
The report records individual imported-layer hashes and resulting template IDs.

The managed directory lived on an exclusively owned 12 GiB ext4 loop mount.
Direct [host command observations](managed-volumes-2026-10-19/host-storage.json)
identify the backing file on host ext4 and LVM on `nvme6n1p3`. This is a
persistent host-file-backed disk test. It is not qualification of a bare NVMe
namespace, drive write-cache behavior, host reboot or sudden power loss.
Only this run's daemon, runtime, VMs, paths, cgroup and loop device were used.

## Real-runtime results

All twelve cases passed in the same attempt. The resource had a logical size
of 20 GiB and initially allocated zero data blocks. Its ID was
`vol_11caf641008d1308580ad5fb93a5bc1d`; backing device/inode were `1798/262207`.
The guest formatted it once as ext4 and wrote 4,194,304 bytes. Later reads
matched SHA-256 `7757fd4a4a314bb1da6d9a60c0d508ff164060c1bc499151cef33d4c946537ed`
and guest filesystem UUID `c7f0873a-a40a-4a19-9141-1e91952ada85`.

| Cases | Observation |
| --- | --- |
| MV-01 through MV-05 | Sparse creation, same-ID retry, owner isolation, conditional/tombstone deletion and concurrent admission. |
| MV-06 | Initially blank and unmounted; explicit format/write/flush/unmount; catalog live attachment and daemon restart preserve attach-only managed descriptor. |
| MV-07 | Claim consumes an existing warm VM and increments the warm-claim counter once. Second writer and held delete return `409` with caller-safe holder details. |
| MV-08 | Each `sync_claims` setting is configured before a fresh claim. SIGKILL and restart preserve its VM generation, bytes and writer exclusion. |
| MV-09 | Release removes old VM; template B uses a different VM and reads the same disk. |
| MV-10 | Actual read-only catalog hotplug completes before a wrapper barrier. Release cancels the pending native PATCH without client disconnect or opening that barrier. During delayed removal, managed delete and competing catalog writer both return `409`; old VMM remains. After removal, replacement reads the same bytes. |
| MV-11 | Public managed detail reports no holders before external storage work. |
| MV-12 | Normal outer unmount succeeds, mount absence is checked, loop buffers flush, read-only `e2fsck -f -n` exits zero, and the same outer UUID remounts. Fresh template B reads the same ID, backing inode/device/size, guest UUID and payload hash. |

MV-10's interrupted PATCH returned HTTP `500` with the native desired/applied
convergence envelope and pending catalog state. It completed within the
fixture's ten-second requirement. The fixture's HTTP client deadline was
thirty seconds, so that response was not a client timeout.

## Source and client checks

- Race-enabled suites passed in `sandboxd`, `sdk/go`, `e2e`, `protocol/wire`
  and `mcp`. Permission fixtures ran with DAC override capabilities dropped.
- All 279 Python SDK tests passed. Python strict typing and Ruff checks passed.
- Darwin build passed for `sandboxd`.
- The original catalog tests retain comparable `VolumeInfo` assertions. Wire
  parity covers summary/detail/holder/create and native live volume types.
- Independent storage, lifecycle and API/SDK readers accepted the committed
  source. They were nonauthors of the sandbox implementation. Runtime receipt
  audits were separate from those source verdicts. Reviewer reuse was required
  by the host's agent capacity; the review did not add model diversity.
- The lifecycle reviewer independently reran the full pool race suite. The
  boundary reviewer independently ran wire parity and synthetic aggregation
  controls that reject each mismatched provenance dimension.

`make go-lint` is **blocked**. The repository-pinned golangci-lint v2.13.2
cannot decode this Go 1.27 toolchain's export-data version 5 and stops in
unchanged `protocol/wire` imports before checking the change. No lint pass is
claimed. Compilation, race tests, typing and formatting are separate results.

## Limits and retained regressions

Fake-engine source tests cover failed metadata commits, prepublication crash
boundaries, retirement with stale claims, safe stale-create collector outcomes,
corrupt/private registry storage, catalog replacement before attach, replacement
dirty markers, uncertain-reference retry cleanup and quarantine after failed
retirement persistence. These are not actual filesystem-fsync or firewall-fault
injections. Stable alias checks do not close a hostile concurrent pathname swap;
trusted catalog path components remain a configuration requirement.

The crash fixture checks exact VMM PID/start identity in code but retains a
boolean result, rather than both raw process records. That comparison cannot
be independently recomputed from the published trace.

No real-VM Go SDK journey, ENOSPC qualification, host reboot, abrupt power loss,
hibernate/wake, grow, managed mesh placement, archive or Kubernetes activation
was performed. Those features must not be inferred from these results.

The first isolated pilot used an incompatible old guest boot chain. A first
qualification attempt caught an immediate serial probe racing guest hotplug;
a later storage attempt rejected an invalid `losetup` query before any unmount.
The retained final attempt uses bounded serial polling, a corrected query, and
fresh claims under both journal settings. Earlier attempts do not contribute
to its pass count. No wrong-repository result contributes to this record.

## Cleanup

The [cleanup receipt](managed-volumes-2026-10-19/cleanup.json) records zero owned
claims, managed resources, holds, backing files and VMs. The owned mount was
removed and loop detached. Six pre-existing foreign processes retained their
PID/start identities. The private filesystem image and evidence remain on disk
for inspection; no shared runtime was stopped.

## Rerun

Use a dedicated KVM Linux host or an exclusively owned runtime configuration,
a matching sandbox guest rootfs, Cocoon and Cloud Hypervisor. Never aim this
fixture at a shared daemon. Build the branch in a clean worktree and supply
that binary; the driver rejects dirty or mismatched VCS metadata.

```sh
python3 scripts/verify-managed-volumes.py setup \
  --run-dir /tmp/owned-volume-mount/run \
  --cocoon-bin /path/to/cocoon \
  --hypervisor /path/to/cloud-hypervisor \
  --rootfs /path/to/matching-rootfs.tar \
  --sandboxd-bin /path/to/clean-sandboxd
python3 scripts/verify-managed-volumes.py verify --run-dir /tmp/owned-volume-mount/run
python3 scripts/verify-managed-volumes.py storage \
  --run-dir /tmp/owned-volume-mount/run \
  --mount-receipt /path/outside-the-mount/mount.json
python3 scripts/verify-managed-volumes.py report --run-dir /tmp/owned-volume-mount/run
python3 scripts/verify-managed-volumes.py cleanup --run-dir /tmp/owned-volume-mount/run
```

Prepare and mount your own ext4 loop filesystem before setup. Keep its receipt
and logs outside that mount. The JSON receipt names `mount`, `image` and `loop`.
The storage command verifies the actual loop backing and mount source before
stopping its owned services. It requires no remaining managed holds. It restores
the mount in `finally` if an offline check fails. Split rootfs layers can be
passed with repeated `--rootfs-layer` options. Keep ownership manifests private;
they contain the run's API tokens.
