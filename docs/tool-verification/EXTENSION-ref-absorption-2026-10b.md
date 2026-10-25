# EXTENSION — second reference absorption from `ref/*` (2026-10-25)

This pass read three public Chinese write-ups dropped in `ref/` and absorbed their *mechanisms* into
the files that already own the topics. None was run end to end; a host-level pass (§Verification pass)
settles the claims that need no device. The record exists so a later reader can tell what changed and
on what footing.

## Sources

Three files, described by shape. Titles, authors, product names, package identifiers and every
per-build address are omitted; none was copied onto the tracked surface.

| File | What it is |
|---|---|
| `vm1.md` | A dual-library commercial shell on ARM64: two SOs, one owning Java/ART checks, the other owning an `init_proc` scheduler with inline-shellcode `exit_group`, three watchdog threads and SMC. Covers dump timing, a syscall-level reader, single-predicate patching and a tiered patch order |
| `vm2.md` | A white-box VM protecting one signing routine: threaded-code interpreter, tens of thousands of obfuscated nodes, and a devirtualization to a straight-line `(op, args)` program with constant table, output map and fixed template |
| `vm3.md` | A native signer behind a JNI shim plus an encrypted body: package/signature checks during `JNI_OnLoad`, an emulator used as an oracle, a differential probe that classifies the cipher, an involution wrapper around a standard stream cipher, and Java/Python encoding drift |

All three are **public secondary sources**. Their own claims are `observed` by their authors; nothing
in them was reproduced here. Mechanisms that need a target are therefore `unverified`, the ordering
judgements built on them are `inferred`, and the host-checkable ones are settled in §Verification
pass. No text, code, key material, offset table or screenshot was
copied.

## What was added

No new reference files. Each mechanism was folded into the file that already owns its topic:

| File | Absorbs | Deliberately does not |
|---|---|---|
| `references/linker-and-soinfo-repair.md` §6.2–6.3 | the dump window that closes inside `JNI_OnLoad` when self-decryption and watchdog startup share it; the raw-syscall reader outside a self-hooked libc; zero-filling unreadable pages so segment offsets survive repair | claim that a dump taken at `android_dlopen_ext` entry is complete; name a specific reader |
| `references/native-tamper-and-suicide.md` §Which site | predicate-first patching (one verdict function versus many kill sites), the tiered grading with the per-tier reason, benign-value selection by caller branch, watchdog enumeration by probe, one tier per run | copy any sample's function table or addresses; assert that a predicate patch covers an unenumerated checker |
| `references/detection-and-anti-analysis.md` §Filter signals | module-filtered signal attribution: ART's implicit `SIGSEGV` on `boot*.oat`/`odex`/JIT pages is the runtime's, and a handler must forward anything outside the target module | claim the discrimination is measured; recommend swallowing runtime signals |
| `references/native-vm-recovery.md` §11 | devirtualization to a runnable program: symbolic input, constant folding, loop/branch elimination, the four artefacts (program, constant table, output map, template), version binding, per-node validation | claim the route works for a VM that reads device state or time; replace the IR-recovery sections |
| `references/protocol-reverse.md` §7 | three black-box probes (header length, determinism, one-byte diffusion width, length law), involution-wrapper algebra, fixed-permutation recognition, and the Java-`URLEncoder` / compression-byte drift that decides the last mile. The probe's original prefix-XOR-only claim was falsified by the host run below and the section now states the corrected discriminator | claim any cipher was classified; assume byte-identical compression is required |
| `references/signature-derived-keys.md` §Variant | a certificate-derived salt concatenated *inside* the digest: why black-box hash search cannot find it, how to read the cached buffer, how to verify on three triples, and the per-build consequence | present the captured constant as an algorithm |
| `references/pitfalls.md` P49–P50 | extraction length masquerading as an algorithm gap; an involution wrapper that cancels | duplicate P42's decoder-desync case or the §7 method |

## Registration surface updated

- `evidence/capability-matrix.json`: three rows — `native-dump-window-and-syscall-reader` and
  `whitebox-crypto-devirtualization-to-program` are `partial` / `route_measured: false` / `unverified`;
  `cipher-classification-by-differential-probe` is `partial` / `route_measured: false` / `inferred`
  after the host checks below; two existing rows
  (`native-terminate-path-neutralisation`, `signature-derived-keys`) had their `limits` extended
  rather than duplicated.
- `references/evidence-summary.md`: three rows.
- `references/coverage/route-inventory.md`: three rows.
- `references/coverage-and-limits.md`: three absorbed-route bullets extended.
- `SKILL.md`, `routing.md`, both READMEs: unchanged. No file, script or symptom row was added, so the
  symptom mirror and the reference/script inventories had nothing to learn.

## Verification pass — host, 2026-10-25

Purpose: separate what the write-ups report from what this host can show, and label per claim rather
than per section. Three tiers were applied: `observed` (a command ran here and its output is below),
`inferred` (follows from a mechanism or a neighbouring measurement), `unverified` (reported by
someone else, not reproduced). No device, protected sample or server was involved, so **no claim
about a target was upgraded**.

```bash
python3 docs/tool-verification/fixtures/verify_absorbed_claims.py
```

```text
PASS mask identity (protocol-reverse section 7, involution)
     65536 eight-bit (x,m) pairs: 0 counterexamples
     200000 random 16-bit pairs: 0 counterexamples
PASS PKCS#7 length law (protocol-reverse section 7, probe 3)
     b=16, p=0..64: 0 mismatches
PASS unreadable page: skip shifts, zero-fill preserves (linker section 6.3)
     expected offset 8199
     skip      -> 4103
     zero-fill -> 8199
PASS hidden salt defeats a visible-parameter search (signature-derived-keys variant)
     36 combinations over 3 algorithms and 4 field orders: 0 hits
     with the salt included: match
PASS compressed bytes are implementation/parameter defined (protocol-reverse section 7)
     level 1 = 49 bytes, level 9 = 48 bytes, identical = False
     both round-trip to the payload
PASS Python percent-encoding differs from Java URLEncoder (protocol-reverse section 7)
     quote      = a%20b~%2A-_.
     quote_plus = a+b~%2A-_.
     Java keeps *-._ and encodes ~ as %7E -- not checked here (no JDK)
PASS AES mode separation (protocol-reverse section 7, probe 2)
     ctr prefix-xor dirty=0/32  one-byte-flip changed=1/32
     cbc prefix-xor dirty=0/32  one-byte-flip changed=32/32
     ecb prefix-xor dirty=0/32  one-byte-flip changed=16/32
     all three modes show zero prefix-XOR: that probe cannot separate them

7 check(s), 0 failed
RESULT=ok
```

### What the run falsified

The absorbed probe said *zeros over the common prefix ⇒ a stream cipher*. Measured on AES-128 with a
fixed IV, **CTR, CBC and ECB all produce zero prefix-XOR** (0 of 32 bytes differ): any deterministic
mode reproduces the ciphertext of a prefix, so the experiment only proves the absence of a
per-message nonce. The discriminator that does work is a one-byte plaintext flip: CTR changes exactly
1 byte, CBC changes every block from the flipped one onward (32 of 32 here), ECB changes exactly one
block (16 of 32, later blocks untouched). The reference now states the corrected procedure; the
capability row records the correction instead of the original claim.

**A label convention was corrected.** `native-vm-recovery.md`'s claim-strength paragraph called the
absorbed mechanics `inferred`. Under the repository's definition (`unverified` = reported by someone
else, not reproduced) the mechanics are `unverified`, and only the ordering judgements are
`inferred`. The paragraph and the checklist now say that; no capability row changed for it.

### Claims the run settles (host only)

| Claim | Where | Now |
|---|---|---|
| `(x & ~m) \| (~x & m) == x ^ m`, and the composition is an involution | `protocol-reverse.md` §7 | `observed` |
| PKCS#7 padded length is `b * ceil((len+1)/b)` | `protocol-reverse.md` §7 | `observed` |
| Zero-filling an unreadable page preserves later offsets; skipping shifts them | `linker-and-soinfo-repair.md` §6.3 | `observed` |
| An unknown salt inside the digest defeats a search over visible parameters | `signature-derived-keys.md` §Variant | `observed` |
| Two compressors/parameters can emit different valid bytes for one payload | `protocol-reverse.md` §7 | `observed` (general) |
| Python's encoder treats ` `, `*`, `~` differently from Java's | `protocol-reverse.md` §7 | `observed` (Python side) |
| CTR / CBC / ECB are separable by diffusion width, not by prefix-XOR | `protocol-reverse.md` §7 | `observed` |

### Claims that stay `unverified`, and what would move them

- **Device-side mechanisms** — the dump window inside `JNI_OnLoad`, watchdog startup, a protector
  intercepting the dump reader. Needs a device and a protected sample: the experiments are the four
  already listed under *What would change a label*.
- **The Java encoder mapping** — no JDK on the analysis host. One captured parameter from a real
  request settles it; until then the mapping is quoted from the JDK contract.
- **liblz4 versus python-lz4** — no lz4 binding here. The general claim is `observed`; the specific
  pair is not.
- **The devirtualization route** — needs a VM binary; nothing on this host can stand in for one.

## Deliberately not absorbed

- **Per-build constants and addresses**: function offsets, unified kill-site addresses, the 32-byte
  salt value, the signing prefix and template string, the package identifier, the shell's own
  `sub_*` names. They are only valid for one build and they carry identity.
- **Performance and effort claims** ("1 ms", "days to hours") — no measurement exists here to anchor
  them.
- **The AI-assisted-analysis narrative** in one source: it is advice about tool use, not a reversing
  mechanism, and it is not reproducible as written.
- **Thread and watchdog tables as data.** The *method* (enumerate by probe, then prove the set closed)
  was absorbed; the table itself would invite applying one build's layout to another.

## What would change a label

One cheap experiment per row, on a device this record never had. The cipher row's host half is
already done (§Verification pass); what remains there is a real body and a real server.

- **Dump window:** dump one protected image at `android_dlopen_ext` entry, repair it, and open it in a
  disassembler with the expected functions present; separately dump inside `JNI_OnLoad` and record
  whether the process survives.
- **Patch grading:** run the same target twice — kill sites only, then the predicate only — and show
  which one survives longer than the observed timer.
- **Devirtualization:** extract one program, run it against a device call on ten inputs, and show
  per-node equality at three checkpoints.
- **Cipher classification:** classify one body with the three probes, then reproduce it and have the
  server accept the request.

Until one of these is recorded, the matrix rows stay `partial` — `inferred` for the cipher row on the
host evidence, `unverified` for the other two — and none may be cited as support for a claim about a
target.

## Gate status

`check_repo.py`, `check_refs.py`, `check_routing.py`, `check_commands.py`, `check_budget.py` and
`pytest -q` were run after the change; the result is in the session record, not in this file. A green
run proves the inventory resolves; it says nothing about whether the mechanisms work.
