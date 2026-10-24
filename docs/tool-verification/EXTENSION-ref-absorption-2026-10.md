# EXTENSION — reference absorption from `ref/*` (2026-10)

This pass read sixteen public Chinese write-ups dropped in `ref/` at the repository root and
absorbed their *mechanisms* into the skill. It did not run any of them. The record exists so a later
reader can tell what changed and on what footing.

## Sources

Sixteen files in four groups. Titles, authors, product names and package identifiers are omitted;
the descriptions are enough to identify the shape without carrying target identity onto the tracked
surface.

| Group | Files | What they are |
|---|---|---|
| Unity / IL2CPP | `unity1.md`–`unity6.md`, `unity8.md`, `unity10.md`, `unity12.md` | Nine write-ups on protected Unity builds: absent/encrypted/embedded metadata, a custom container VM, a two-stage native loader, HybridCLR IL-body encryption, a version-lying metadata header, live-image dumping and ELF repair, a runtime IL2CPP bridge, an AssetBundle wrapper and a CDN manifest |
| SO / linker | `so1.md`, `so2.md`, `so4.md` | Two source-reading walkthroughs of the Android `dlopen` pipeline and packer design (Android 5.0 and 8.x), plus a Frida cookbook for native/Java hooks |
| VM protector | `vmp1.md`, `vmp2.md`, `vmp3.md` | A teaching series and a practical crack on x86 VMProtect-style targets: virtualized dispatch, virtual eflags, NAND lowering, trace search |
| Python bytecode | `py1.md` | Static unpacking of a Pyarmor build with a modified `pycdc` |

All sixteen are **public secondary sources**. Their own claims are `observed` by their authors when
they show a command and output; nothing in them is reproduced in this repository. The absorbed
mechanics are therefore `unverified` here, and the *ordering judgement* built on them is
`inferred`. No text, code, key material, offset table or screenshot was copied.

## What was added

Four reference files, each with its own claim-strength paragraph and boundary:

| File | Absorbs | Deliberately does not |
|---|---|---|
| `references/il2cpp-protected-metadata.md` | Metadata triage (absent/0-byte/encrypted/embedded/version-lie), consumer-side dump, 0x10C header sizing, repeating-key XOR, custom bytecode-VM container, XXTEA, length-derived string keys, live-image dump and ELF repair, HybridCLR IL-body decryption, AssetBundle header transforms | Recover IL2CPP native code or build an opcode map; explain a specific dumper's internals |
| `references/linker-and-soinfo-repair.md` | `dlopen` pipeline as a loader spec, `load_size`/`load_bias`, `seg_page_offset`, `DT_HASH`/`DT_GNU_HASH`, relocation targets and the two biases, APS2, minimal `soinfo` repair, anti-dump header XOR, dump points, constructor timing | Implement an unpacker; guarantee `soinfo` offsets across Android versions |
| `references/vm-protector-analysis.md` | Envelope triage, VM_DATA/VM_CONTEXT/vEIP/vStack, central vs direct-threaded dispatch, data-anchored breakpoints, forged returns, trace-by-constant, virtual eflags, NAND lowering, branchless select, static rebase caveats | Reconstruct the guest instruction stream; replace handler slicing in `native-vm-recovery.md` |
| `references/python-bytecode-recovery.md` | Pyarmor key schedule, AES-CTR nonce rules, the 12-byte nonce-XOR VM, version-gated `pyc` parsing, extra-section TLV, per-code-object and per-string decryption | Run the recovered module; generalise field offsets across Pyarmor versions |

### Existing files touched

- `unity-runtime.md` — the "metadata does not parse" branch now hands the protected case to the new
  file instead of implying that a retry with another dumper is the answer.
- `framework-runtimes.md` — Python runtimes (Chaquopy/Kivy/BeeWare) added to the identification
  table, with the new file as the next step.
- `native-vm-recovery.md` — a cross-link for the case where the missing piece is *what a handler
  computes* (virtual eflags), not *where the dispatcher is*.
- `code-virtualization-and-custom-linkers.md` — a cross-link for when the loader itself becomes the
  object of study rather than its validation check.

## Registration surface updated

- `SKILL.md` symptom index and the `routing.md` mirror: five rows, identical first cells.
- `routing.md` reference index: four rows.
- `evidence/capability-matrix.json`: four rows, all `partial` / `route_measured: false` /
  `unverified`; the existing Unity row's evidence list now names the companion file.
- `references/evidence-summary.md`: four rows.
- `references/coverage-and-limits.md` and `references/coverage/route-inventory.md`: four documented
  routes, and the not-covered statement now names both Unity files.
- `README.md` and `README.zh-CN.md`: tree entries and a scope clause.

## Second pass — gaps found by auditing the first pass

The first pass kept the four new references at the level of the primary mechanism and left several
secondary mechanisms in the sources. An explicit file-by-file audit found these, and they are now
absorbed into the files that already own the topic (same `unverified` / `inferred` labels):

| Missed mechanism | Now in |
|---|---|
| Staged loader that decrypts a DEX from an asset, selects a payload by ABI, and patches an 8-byte tail | `code-virtualization-and-custom-linkers.md` §staged loaders |
| IL2CPP live object graph (`Il2Cpp.gc.choose`, getter invocation) and `Il2Cpp.dump(name, path)` | `unity-runtime.md` §5 |
| ARM64 app on an x86 host: translation runs the app but not an ARM64 `frida-server` | `environment.md` §emulator notes |
| MessagePack as a self-describing body; mutate request before response | `protocol-reverse.md` §1.1, `server-api.md` |
| A delayed detection that is a `sleep`/`nanosleep` timing measurement | `detection-and-anti-analysis.md` §timing-delayed checks |
| A dynamically loaded dex visible as a `(deleted)` mapping | `advanced-unpacking.md` §read the map |
| `RegisterNatives` table layout, `dlopen` gating, instruction+4 reads, Thumb NOP patch inside `call_function`, JNI argument shapes, OLLVM call-graph triage | `dynamic-frida.md` §native registration |
| Trace call-site anchoring, `rel32` resolution, back-edge hot-loop suppression | `vm-protector-analysis.md` §4.1 |
| Branchless `max` arithmetic | `vm-protector-analysis.md` §6.2 |
| Encoded handler tables (`table[i] + constant`) and the one-register/benign-landing dispatcher invariant | `native-vm-recovery.md` §2.1-2.2 |
| The `29.1` `genericMethodPointersCount` misdetection on a large `.so` | `il2cpp-protected-metadata.md` §5 |

### Deliberately not absorbed

- **Target-specific constants**: per-sample addresses, AES keys, section names, package ids, CDN
  hosts, device serials and the write-ups' own scripts. They would be reused wrongly and they carry
  identity; the reference files say the constants must be re-derived.
- **One-target asset pipelines**: Live2D `moc3` parsing, USM video reconstruction, the CDN manifest
  delta and the Blender import conventions. They are not APK-reversing mechanisms and belong to an
  asset-extraction skill; `unity-runtime.md` §6 keeps the audit question, not the pipeline.
- **Middleware-specific audio decryption** (CRIWARE ACB) and the GUI-only steps of the cited
  debugger sessions.
- **Secure-coding advice** (constant-time comparison) that is not a reverse-engineering route.
- **Exact opcode tables** from a challenge VM. The procedure for deriving one is covered in
  `native-vm-recovery.md`; copying the table would invite applying it to a different ISA.

## What would change a label

Per file, one cheap experiment turns the `unverified` mechanism into a local `observed`:

- **IL2CPP metadata:** decrypt one file to a valid `0xFAB11BAF` and have Il2CppDumper accept it;
  separately dump one live image and name one function in the disassembler.
- **Linker:** load a trivial `.so` from memory with the arithmetic in the file, resolve one symbol
  through the repaired `soinfo`, and dump one protected image at `LoadSegments`.
- **VM protector:** trace one protected comparison, find the virtual flags slot, force the value, and
  show the failure path disappear while the VM remains intact.
- **Python:** parse one `.pyc`, show the extra-section counts matching the file, decrypt one code
  object, and execute the recovered module to the same output as the original.

Until one of these is recorded, the capability matrix rows must stay `partial` / `unverified`, and
a reader must not cite them as support for a claim about a target.

## Gate status

The structural gates were run after the change: `check_repo.py`, `check_refs.py`,
`check_routing.py`, `check_commands.py`, `check_budget.py`, and `pytest -q`. A green run proves
the inventory resolves and the index mirrors agree; it says nothing about whether the mechanisms
work. That distinction is the point of the labels above.
