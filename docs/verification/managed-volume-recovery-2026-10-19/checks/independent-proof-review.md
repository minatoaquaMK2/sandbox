# Independent proof-method review

Verdict: ACCEPT for the proof methods at `64e88662893de5f919e46e45871e7c13f75e8f50`. This is not an acceptance of an uninspected runtime result or publication bundle.

Reviewer: Codex. The runtime does not expose a more precise model identity. This reviewer authored R2/H1 production changes and does not provide their independent production gate. The reviewed proof scripts were authored by other agents. Finished-reviewer reuse follows the stated capacity exception.

## Scope and method

Compared `5f89499a8be3580b2fade310ce4b5ba5f6a435fa` with the exact target for `scripts/verify-managed-volumes.py` and `scripts/fixtures/managed-volume-cases.py`. Read their ownership, recording, report aggregation, startup binding, and cleanup context, and the unchanged runtime fault wrapper. Read the recovery design and the comment-sicko instructions. No hardware, mounts, processes, or actual evidence were changed or driven by this reviewer.

Reviewed script SHA256 values:

- `scripts/verify-managed-volumes.py`: `c5c6fd9cedec7d5f96cb25b7c1a5a8a741b7d2046d5d9796d7d4a26d685923b5`.
- `scripts/fixtures/managed-volume-cases.py`: `9b501699acccdb6dd3708151faed386ab1deb4953f9df48e1b838efcdd557e23`.

Isolated synthetic checks ran successfully with `python3 /tmp/sandbox-proof-review/probe.py`; results are in `/tmp/sandbox-proof-review/probe.log`. They use source obtained with `git show` at the target. Offline journal mutation rejects unowned IDs, preserves unrelated fields, hashes original input, and omits synthetic root and claim credentials from its receipt. Report aggregation accepts matching fifteen-case receipts and rejects changed attempt, binary, fixture binding, or a failed case. These checks stub the process-stopped and source-binding boundaries and therefore do not prove those boundaries or any real runtime behavior. Both scripts also compiled without execution.

## Findings and closure

No outstanding blocking method finding in this delta.

The earlier MV15 assertion required `managed_volume_dir` in every diagnostic, which would incorrectly reject the new backing-alias guard. `5180e2d` selects the actual backing-storage diagnostic for alias cases. Nonzero exit, preserved marker, absent registry, and unchanged real resource remain required.

The first MV13 runtime trial exposed Cocoon's missing `socket_path` on a stopped VM. `64e8866` allows an absent socket only for a stopped record. The case still starts with an owned running socket, records the original process identity, stops that exact uniquely named VM through the dedicated runtime configuration, waits for the original PID to disappear, and looks up that same name in the dedicated inventory before restart. Running records with missing or foreign sockets still fail. The earlier failed trial is not successful evidence and must remain distinguishable from the new attempt.

## What the methods establish

MV08 retains before/after PID, process start, and command receipts for each sync setting instead of only claiming a boolean identity match.

MV13 creates a real unclaimed VM while a managed resource exists, stops its VMM, observes the retained stopped inventory entry, restarts sandboxd, and requires readiness, inventory removal, and unchanged managed resource identity. This exercises stopped-orphan recovery. It does not replace tests for unreadable process metadata, creating records, or tracked process generations.

MV14 edits only explicitly owned healthy claim rows while the owned daemon is stopped, preserving all registry bytes. One claim receives the exact quarantine reason and another an ordinary failure reason. An exact-name `vm rm --force` wrapper refusal must actually be reached. The original quarantined VMM must remain alive while its public hold is retiring and competing writer/delete operations return 409. Clearing the refusal must lead to old-process and inventory absence, hold removal, and successful replacement reading the marker. The ordinary failed control must remain alive and claimed until explicit release. Receipt flags correctly describe this as an offline seeded failure state plus injected command refusal. It does not inject a real egress failure or registry fsync failure, and exercises the recorded sync setting only.

MV15 executes the exact bound sandboxd binary against eight disposable unsafe layouts. The two alias cases precreate only private fixture directories and a marker; they require the marker to survive and no registry to appear. Original layouts require refusal before directories appear. `/bin/false` is the fixture runtime command. The case also checks the real registry digest, backing identity, resource ID, and guest marker after these probes. This proves the selected layouts, not hostile concurrent alias changes or every possible configuration.

## Ownership, privacy, and evidence boundaries

The new mutation requires the dedicated `data_dir`, stopped owned daemon, remembered owned claim IDs, and exact row IDs. The runtime wrapper fault is limited to one selected owned VM name; the ordinary-failure control checks against overbroad cleanup. Existing destructive cleanup uses the dedicated instance, resource IDs, and process/socket ownership checks. An interrupted stopped orphan can cause cleanup to refuse on its missing socket rather than broaden deletion authority; owner recovery may be needed before cleanup completes.

Direct receipts contain process identities, resource metadata, selected failure strings, hashes, and command observations, not copied claim journal rows. API-token values are checked before receipt emission. MV15 separately checks its ephemeral credential against startup output. Its nested fixture `sandboxd.json` files intentionally contain ephemeral bearer values. Publish only direct case evidence files, not the nested `unsafe-layout-*` directories, private ownership manifest, or daemon configuration. A final publication credential scan remains necessary; this source review is not that scan.

The verifier freezes case IDs, source revision, SDK revision/content digest, fixture hashes, clean binary VCS metadata, and binary digest per attempt. Case boundaries check current source/fixture/SDK content and both on-disk and running executable bytes. Aggregate report success requires all fifteen current receipts with matching provenance. Runtime acceptance must inspect those exact receipts, including IDs and case evidence, plus final storage and cleanup receipts. No earlier twelve-case or failed-attempt receipt substitutes for this new attempt.

## Remaining limits

Actual final fifteen-case run, offline storage step, cleanup, and published credential scan are outside this method-only verdict until their receipts are reviewed. No host reboot, physical power loss, actual failing fsync, or real egress-fault durability is established by these new methods. Fifteen selected cases are not a claim to cover every historical feature-map case.

The scoped comment-sicko pass found no introduced comments, narration docstrings, or suppressions to remove. Proposed deletions: zero. MUST KILL flags: zero. Existing baseline comments were outside this delta.

The Prove It Works principle shaped the separation between source-method acceptance, isolated helper checks, and final runtime evidence. Model the Domain shaped review of seeded quarantine versus ordinary failure as distinct recovery states, rather than treating every Failed row as teardown authority.

## Publication formatting follow-up

Independently compared the working fixture with qualified commit `64e88662893de5f919e46e45871e7c13f75e8f50`. The entire fixture change is the three-line reflow of the `owned_vm` assertion at line 490. Python `ast.dump(ast.parse(source), include_attributes=False)` is identical for both files. The formatted fixture SHA256 is `a81c49637eb061a9af964d96e93600497a9a213a633ba1554a3fd5ab3fc9ba1e`; the qualified fixture retains SHA256 `9b501699acccdb6dd3708151faed386ab1deb4953f9df48e1b838efcdd557e23` in actual receipts. This formatting change introduces no behavior change and needs no repeat VM run. Keep the qualification pinned to the original commit and fixture hash, with the later publication commit described as documentation plus AST-equivalent fixture formatting. This check did not audit the proposed 67 published artifacts or their credential redaction.
