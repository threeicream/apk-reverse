# EXTENSION — third audit of the `ref/*` drop folder (2026-10-27)

`ref/` still held the sixteen write-ups absorbed on 2026-10-24 (`EXTENSION-ref-absorption-2026-10.md`).
Their mtimes were unchanged, and nothing in the folder matched the 2026-10-25 set that was absorbed in
place. So this pass was **not** a re-absorption: it re-read all sixteen, compared every generalisable
mechanism against what the skill already says, and ran the host-checkable part of what it found. Nine
mechanisms were still absent, one absorbed sentence turned out to be wrong, and one procedure is now
`observed` instead of `unverified`.

## Sources

The same sixteen files, in the same four groups as the 2026-10 record (Unity/IL2CPP nine, linker three,
x86 VM protector three, Pyarmor one). Titles, authors, product names and package identifiers are omitted
here for the same reason as before: they carry identity and nothing in the tracked surface needs them.
All are public secondary sources, `unverified` in this repository unless the verification pass below
says otherwise.

## What was added

No new reference files — every mechanism went into the file that already owns its topic.

| Mechanism | File | Why the existing text did not cover it |
|---|---|---|
| The shipped Pyarmor blob is wrapped once more: outer container → per-code-object → per-string, three nonce scopes on one master key, and a live dump is therefore structurally incomplete | `python-bytecode-recovery.md` §2.2 | §3 opened with "the protected file is a normal `.pyc` with extra fields", which is the second layer, not the file you are handed |
| Mirror the host register width, not just the register clobbers, when reimplementing the 12-byte key VM | `python-bytecode-recovery.md` §2.1 | §2.1 named the `idiv` clobber; 32-bit wrapping and truncating division were unstated, and they fail the same way |
| Python compiled away (Nuitka / Cython / `pyd`): no `.pyc` is not "no Python" | `framework-runtimes.md` identification table | the Python row implied the runtime always arrives as bytecode |
| A rebuilt `libil2cpp` announces itself in the ELF tables (`JNI_OnLoad` export, own `DT_INIT`/`init_array`, `SHT_LOUSER` section) | `il2cpp-protected-metadata.md` §1.1 | the triage table sent "registration search returns 0" straight to the live-image dump; the injected entry point is cheaper to find and is what the dumper's refusal is reacting to |
| A container VM's block schedule decides what a unit test is: fixed-size blocks with a truncated tail and no cross-block state vs a chained context | `il2cpp-protected-metadata.md` §3.2 | the section specified the container layout and stopped at "replay the program"; the call site is what says whether block 0 is a valid test |
| When the literal cipher lives in the VM, drive `String::NewLen` over every index instead of reversing the cipher — and use it as a completeness proof | `il2cpp-protected-metadata.md` §6 | the hook was documented as observation only; enumerating the index space is a different, stronger route |
| A VM can live in the managed layer: opcode array + cursor + `Dictionary<int, delegate>`, handler indices enrolled in the constructor | `unity-runtime.md` §when the managed layer is itself the interpreter | every VM file assumed a native interpreter; `native-vm-recovery.md` now says so explicitly and cross-links |
| Static array literals are field defaults materialised by `RuntimeHelpers::InitializeArray`, not bytes in `.rodata` | `unity-runtime.md` same section | the absence of a table in `.rodata` was being read as "derived at run time" |
| Hook the framework crypto primitive (BCL AES provider, `javax.crypto`), not the app's obfuscated wrapper | `unity-runtime.md` §5 | §5 polled the app's own class; the stability of framework class names under obfuscation is the point |
| A comparison gate is a prefix oracle: instrument the comparator's counter, and read the fail-path cost to decide whether the oracle is open | `account-gates.md` Step 2b | the file classified gates by authority and never considered that the comparison itself leaks the expected value |
| Debugger-side stop policy: `SIGPWR`/`SIGXCPU` suspend-to-crash, one database per activity, input injection into a paused process | `ida-so-debugging.md` §8 | the debuggable-side failure modes were documented; the failures caused by the debugger's own defaults were not |

### A claim that was corrected, not added

`python-bytecode-recovery.md` §5 said an unset `nonce[15]` "produces a stream that decrypts the first
block plausibly and then diverges". Counter mode does not have that state: the keystream for block *i*
is `E(nonce || counter_i)`, so a different nonce byte changes the output from block 0. Measured below.
The paragraph now says what happens (every block wrong; an unset tail makes the result
non-reproducible) and tells the reader to check a known prologue rather than "a plausible body".

## Registration surface updated

- `evidence/capability-matrix.json`: two rows, `il2cpp-managed-layer-bytecode-vm` (`partial`,
  `route_measured: false`, `unverified`) and `comparison-cost-oracle` (`partial`,
  `route_measured: false`, `observed` — the host half only).
- `references/evidence-summary.md`: the same two rows, with the same labels.
- `references/coverage/route-inventory.md`: one new row (the comparison oracle) and three extended rows
  (Unity, protected IL2CPP, Python).
- `references/coverage-and-limits.md`: three bullets under "Covered by documented routes", each naming
  which half is measured.
- `SKILL.md`, `routing.md`, both READMEs: unchanged. No file, script or symptom row was added, so the
  symptom mirror and the inventories had nothing to learn. That is also why the token budget did not
  move.

## Verification pass — host, 2026-10-27

```bash
python3 docs/tool-verification/fixtures/verify_ref_claims_10c.py
```

```text
PASS CTR: nonce tail changes block 0 (python-bytecode-recovery section 5)
     keystream block 0 differs in 16/16 bytes
     ciphertext block 0 differs in 16/16 bytes, blocks 1-2 in 32/32
     negative control, nonce against itself: 0/48 bytes differ
     so there is no "first block decrypts, rest diverges" state -- every block is wrong
PASS comparison cost is a prefix oracle (account-gates Step 2b)
     prefix 0/15 -> early-exit 1, full pass 15
     prefix 1/15 -> early-exit 2, full pass 15
     ...
     prefix 15/15 -> early-exit 15, full pass 15
     full pass over the same candidates: [15]
     negative control, identical inputs through the early-exit build: 15 (must be 15)
     early exit: work grows one unit per correct prefix byte; full pass: constant
PASS metadata header size by backward walk (il2cpp-protected-metadata section 2.1)
     declared 0x1140, forward scan 0x1140, walk from 0x10c -> 0x1140
     negative control, off-grid start 0x110 -> 0x1120 (must differ)
     magic/version zeroed in this fixture: the walk uses only offset/count pairs

3 check(s), 0 skipped, 0 failed
RESULT=ok
```

Three labels changed as a result: the counter-mode statement in §5 is now `observed` (and corrected),
the comparison-cost separation in `account-gates.md` is `observed` for the synthetic case only, and
the backward header walk in §2.1 is `observed` on a synthetic header. **No claim about a target was
upgraded** — no device, sample or server was involved.

### The fixture was audited before it was trusted

The first draft passed all three checks and was still wrong in one of them: the comparison check
incremented its own counter inside the loop it was measuring, so `work == k + 1` restated the Python
source and could not fail for any real reason — the repository's "a limit that cannot fail is
decorative" defect, in a check that was about to carry an `observed` label. Three changes:

1. **Measured on compiled code.** The two comparators are now C, built with `-O2` and called through
   `ctypes`; the question is what a compiler emits for `break` on mismatch, which an interpreted loop
   cannot answer about itself. Without a compiler the check reports SKIP rather than PASS.
2. **Every check carries a negative control** that must come out empty: the same nonce twice (0/48
   bytes differ), identical inputs through the early-exit build (15, i.e. a full pass), and an
   off-grid walk start (`0x110` yields `0x1120` instead of `0x1140`).
3. **The verdict travels as a return value, not through a global list.** `main()` built its failure
   count from the list `report()` appended to, so a check that returned False without printing would
   have been invisible; it now counts the return values and reports skips separately.

`tests/unit/test_verify_ref_claims_10c.py` injects the wrong claim into each check and requires the
failure — full-pass mislabelled as early-exit, early-exit mislabelled as constant, an unchanged nonce,
an off-grid walk, a pair table whose declared and scanned lengths disagree — plus the skip semantics
(a host with no `openssl`/compiler exits 0 with SKIP) and the exit-code plumbing. The AES probe needs
`openssl`; the comparison probe needs a C compiler; the header check needs nothing.

## Deliberately not absorbed

- **Per-build constants and identities**: offsets, keys, package ids, function counts, the articles' own
  scripts. Same rule as the two earlier passes.
- **Asset and media pipelines** (Live2D `moc3`, video reconstruction, Blender conventions) and the
  CDN-manifest delta. One candidate survived this audit — "an index pulled from a device is a cache
  subset, not the catalogue" — and was dropped deliberately: it is a provenance rule for a download
  pipeline, and `server-config-and-updates.md` is not an asset-extraction file.
- **In-memory patch hygiene** (write the operand, restore `r-x`) from one article: the distinct part is
  one sentence, and `native-and-so.md` already carries the "which copy is mapped" rule that decides
  whether a patch matters at all. Recording it would have added a fourth file to a single idea.
- **Performance and effort claims**, and the articles' commentary about tooling quality.

## What would change a label

One experiment per row, none of which this record could run:

- **Managed-layer VM**: recover one opcode table from a `dump.cs` interpreter and show an instruction
  stream that reproduces a known in-game value. That moves the row to `observed`; today only the shape
  is documented.
- **Array literals**: hook `InitializeArray` on a live build and read back a key that the same build's
  `.rodata` does not contain.
- **Comparison oracle**: run the counter against one real serial gate and show the work grows with the
  correct prefix. On a device, use the comparator's counter, not the clock — a timing-only attempt is
  expected to fail and would not move the row.
- **Pyarmor outer layer**: decrypt one shipped blob, show the pyc magic appearing only after the outer
  pass, then decrypt one code object and run the recovered module.
- **Rebuilt `libil2cpp`**: `readelf` a stock library and the protected one side by side and show the
  three markers absent/present.

## Gate status

`check_repo.py`, `check_refs.py`, `check_routing.py`, `check_commands.py`, `check_budget.py` and
`pytest -q` were run after the change and are green (796 passed, 209 skipped, 25 xfailed; eight of
those tests are the fixture's own falsifiability cases). A green run
proves the inventory resolves and the mirrors agree; it says nothing about whether any mechanism works
on a target, which is what the labels above are for.
