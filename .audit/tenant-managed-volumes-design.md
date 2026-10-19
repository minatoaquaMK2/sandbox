# Correct-target architecture

Baseline f90af50 already owns desired/applied live volume state through volumeRun. Preserve its APIs and state machine.

Candidate A ports the old imperative live mutation and cancellation map. Reject: it would replace #339 and duplicate ownership.

Candidate B adds managed resource/hold persistence beside the existing flat claim journal, integrating its write-ahead registry into existing volumeRun registration, stage, confirmed-commit, release transfer and startup recovery. Choose B.

Resource and hold types remain separate. Resource IDs are immutable; holds have attaching/claimed/retiring variants and exact VMM boot/PID/start identity. The durable ref set must cover desired, applied and active run refs. Catalog-only claims remain on their existing path.

Claim admission creates a stable hold ID before VM effects; binding persists the exact process identity before DiskAttach. Finalization preserves ID and activates the hold. Reconcile recovers holds before pruning the flat claim journal or stale sweeps. Unknown creating records use safe runtime collector proof; Busy/error fails closed. Managed removal requires both fresh runtime absence and exact process death even when Remove reports success.

Live managed resources are immutable in this phase. Existing managed entries can be retained unchanged in PUT/PATCH targets. Read-only catalog changes on managed claims continue using volumeRun. Stage persists possible catalog refs before claim intent and device effects. Only a successful journal/device convergence trims those refs and their counters. Failed or uncertain writes retain the union through release/restart. finishVolumeRun must not silently discard managed durable refs.

Release/reap commit managed retirement before cancelling volumeRun and dropping the claim. Registry failure retains/fences the public row; claim-store failure may restore the row while durable retirement remains the closing fence. Do not add a second cancel map or hold Transition across guest I/O.

Managed endpoints require explicit authenticated root or tenant bearer, preserving current #339 management-token auth for live endpoints. Unknown/denied names share a response, root static peer fallback remains. Go/Python CRUD stays node-local, context/timeout bounded, and keeps full structured holder errors.

Every filesystem ancestor owner must be trusted root/daemon, even sticky. Backing paths are ID-derived and inode/device/size-pinned. No grow, managed live writable changes, capture lifecycle, managed mesh placement or deployment activation is added.
