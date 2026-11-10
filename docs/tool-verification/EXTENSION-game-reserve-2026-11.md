# EXTENSION — absorbing the reverse-engineering half of `game-reserve` (2026-11-09)

A public game-preservation skill was cloned at the repository root (`game-reserve/`). It is
mostly a workflow for turning a dead server into an offline build. That workflow is **not** what this
pass took. This pass read the case reports and the pitfalls for the reverse-engineering mechanisms
they contain and landed only those: how the Unity/Lua script layer is found and repaired, how
AssetBundles are checked and rebuilt, how a half-encrypted Mono assembly is read, how LayaAir's Conch
cache is recomputed, and what recon should measure before a route is chosen.

## Sources

- `game-reserve/` (the clone at the repository root) — its recon reference (logic-layer table,
  encryption map, CRC log, resource-completeness check), four anonymised case reports (Unity + Lua,
  LayaAir + JS, Unity Mono + SLua, native Kotlin), and its patch/pitfalls notes (UnityFS rebuild
  traps, TextAsset read-back, hot-update merge, R8 minSdk branches, `os.date` race).

All are public secondary sources. Their case reports are `observed` **by their authors**; nothing in
this repository executed them. Identifiers, package names, hosts, keys, offsets and the source's own
scripts were deliberately not copied.

## What was added

One new reference file, because the topic had no owner:

| File | Covers | Why no existing file owned it |
|---|---|---|
| `references/unity-lua-and-assetbundles.md` | Unity + Lua (xLua/tolua/SLua) container discovery, script decryption and Lua 5.1 header repair, loader bytecode-only check, AssetBundle CRC source, UnityFS partial-encryption windows, bundle rebuild traps (layout loss, stripped dependency null, compressed == raw), added/replaced TextAsset read-back, half-encrypted Mono assemblies and the publisher shell | `unity-runtime.md` owns Mono/IL2CPP and `il2cpp-protected-metadata.md` owns protected metadata; neither owns a Lua layer or UnityFS container editing. `packers.md` owns generic shell identification, not the Mono-assembly decryptor shape |

Existing topic files were extended, not duplicated:

- `references/framework-runtimes.md` — a **LayaAir native (Conch)** section: identification, the
  path-addressed cache, the DCC filetable checksum, metadata regeneration from shipped content, the
  loader patch and the startup-delay race, plus the Laya render-loop freeze and poisoned-XHR shapes.
- `references/recon.md` — Unity + Lua and LayaAir rows in the code-location table, and a
  **§1c** for resource completeness and the encryption map (manifest diff, player backup, entropy is
  not encryption, fixed prefixes, config-table field check, separate "unreadable" from "not in hand").
- `references/repack-and-sign.md` — **renaming the package** across binary AXML, the `resources.arsc`
  package block and the launcher label, with the validation that both builds coexist.
- `references/split-apk.md` — the narrow manual resource merge through `apktool` that the source's
  native case used, with the condition that makes it safe and the collision that stops it.
- `references/dex-patching.md` — deleting specific calls from an original smali method instead of
  hand-rewriting a lifecycle method, removing the argument-preparation instructions, and putting new
  logic in an extra dex behind one `invoke-static`.
- `references/packers.md` — PairIP as a target-selection signal (Play licensing plus partial code
  virtualization): prefer an older/regional build without it rather than fighting a re-signed suicide.
- `references/pitfalls.md` — **P51** (R8 deleted the low-API branch when `minSdk` was lowered),
  **P52** (a decompiled Lua file does not match its name because the writer's `read()` returns the
  template/original bytes) and **P53** (a retained AssetBundle returns null after its dependency was
  stripped).
- `SKILL.md` and `references/routing.md` — two symptom rows: a Lua decompiler rejecting every
  script with `non-standard lua format`, and a re-signed Unity/Mono build exiting cleanly with code
  4 two seconds in.

## Deliberately not absorbed

- **The offline-revival workflow itself**: feasibility verdicts, fake local servers, virtual-clock
  testing, player-order playtest, save-preserving release, media/OCR recovery, distribution and the
  unattended-run playbook. It is a legitimate body of work, but it is a product workflow rather than
  an APK-reverse mechanism, and the first pass that imported it was corrected for exactly that.
- **Target-specific constants**: package names, hosts, keys, offsets, counts, paths and the source's
  scripts.
- **The source's local-server implementation**: `RPCWaitSend` handling, entity-property bags and the
  rest belong to a game-revival project, not to this skill's protocol-reverse files.
- **The media/OCR and night-shift stacks**: no script surface is imported that this pass cannot test.

## Registration surface updated

- `references/routing.md`: one reference-index row; two symptom rows mirrored from `SKILL.md`.
- `README.md` and `README.zh-CN.md`: one entry in the structure block.
- `evidence/capability-matrix.json`: `unity-lua-and-assetbundle-recovery` and
  `layaair-conch-dcc-recovery`, both `partial` / `route_measured: false` / `unverified`.
- `references/evidence-summary.md`: the same two rows.
- `references/coverage/route-inventory.md` and `coverage-and-limits.md`: two documented-route rows
  and two bullets.
- `evidence/known-limitations.md`: one "never exercised" bullet.
- `.gitignore`: the upstream clone is ignored, so a later `git add -A` cannot commit it.

## Verification

None of the absorbed reverse-engineering mechanisms is `observed` in this repository. No Unity or
LayaAir package was decrypted, no bundle was rebuilt, no Mono assembly was reconstructed, and no
device build was installed. The checks performed here are structural: the new file and every changed
section resolve, the symptom mirror agrees, and the registration surface names the new capability.

## What would change a label

- **Unity + Lua**: decrypt one anonymous Unity+Lua package, decompile a script, patch one anchor,
  rebuild the bundle, install it and show the changed behaviour after a cold start, with a control
  build. That moves the Lua half toward `observed`.
- **UnityFS**: rebuild one bundle with the same layout and show it loads; then reproduce the
  compressed-size-equals-raw crash in a control and fix it in one field. The single-field experiment is
  the cheapest.
- **Mono half-encryption**: reconstruct one PE header from the documented landmarks and have a
  decompiler open it; the shell-recovery half additionally needs the original process.
- **LayaAir DCC**: recompute the filetable for a package and show the engine accepts the regenerated
  metadata offline. The checksum algorithm is arithmetic and can be host-tested on synthetic files;
  the full route still needs a package.

## Gate status

Run after the change:

```text
python check_repo.py && python check_refs.py && python check_routing.py \
  && python check_commands.py && python check_budget.py && python -m pytest -q
```

Result on 2026-11-09: `check_repo` 0 problems; `check_refs` 489 reachable references, 0 dangling,
0 warnings; `check_routing` coherent (72 symptom rows, 63 reference rows, 64 script rows);
`check_commands` 196 checked, 0 drift; `check_budget` 448 lines / ~12,987 tokens, 0 failures,
0 warnings; `pytest` 796 passed, 209 skipped, 25 xfailed. A green run proves the inventory resolves
and the mirrors agree; it says nothing about whether a decrypted script or a rebuilt bundle works,
which is what the labels above are for.
