# Unity + Lua, AssetBundles, and half-encrypted Mono assemblies

Load this when a Unity APK keeps its game logic in Lua (xLua / tolua / SLua), when the thing you need to
edit is an AssetBundle rather than an assembly, or when a rebuilt Unity package fails in a way that
looks like the patch: a decompiler rejects every script, a bundle loads as null, a repacked bundle
crashes only on device, or a re-signed Mono build exits cleanly a second or two after the splash. It
is the script-and-asset half of Unity; `unity-runtime.md` owns Mono/IL2CPP identification and the
managed-code route, and `il2cpp-protected-metadata.md` owns protected IL2CPP metadata.

**Claim strength.** Absorbed from a public game-preservation skill's anonymised case reports: one
Unity + Lua target (1,443 encrypted TextAssets, a Lua bundle, CRC in an AssetBundle manifest) and one
Unity Mono + SLua target (8,420 Lua 5.1 TextAssets, a publisher shell that decrypts the first 4 KB of
each assembly, a 1.2 GB micro-client). The source reports these as work performed on real devices;
**this repository has run none of it** — no Unity package was decrypted, no bundle rebuilt, and no
Mono assembly reconstructed here. Every mechanism below is therefore `unverified`, and the counts
and offsets are the source's, not this repository's measurements. What generalises is the failure
shape, not the constants.

## 1. Recognise the shape before choosing a tool

| What is in the package | Where the logic is | Route |
|---|---|---|
| `libunity.so` + `libmono*.so` + `assets/bin/Data/Managed/Assembly-CSharp.dll` | C# IL | `unity-runtime.md` §Mono |
| `libunity.so` + `libil2cpp.so` + `global-metadata.dat` | native + metadata | `unity-runtime.md` §IL2CPP |
| `libunity.so` + a `luascript` bundle or thousands of Lua `TextAsset` entries | Lua source or Lua 5.1 bytecode | this file §2 |
| `assets/AssetBundles/<platform>/` with per-bundle `.manifest` files | assets, prefabs, textures, sometimes scripts | this file §3–§4 |
| `Application` is a vendor shell class + `libtprt.so` / `__tpinfo.tsa` | shell decrypts managed assemblies at run time | this file §5 |

The first question is not "how do I decrypt Lua" but **which layer owns the behaviour**. A Lua game
can have almost no interesting C#: the C# boots the engine, loads a bundle and calls into Lua. In that
shape, editing IL is the wrong layer even when the IL is readable.

## 2. Getting Lua out of a Unity package

### 2.1 Find the container and the key

Scripts usually live in one of three places: a dedicated bundle such as `luascript`, individual
`TextAsset` entries inside many bundles, or a loose file list such as `all_lua_files.lua` (which is
often the one plaintext index that names the rest). Locate the loader first: a C# method with names
like `LuaScriptKey`, `ScriptKey`, `Key()` or `LuaRuntimeConfig` is where the key is chosen.

The source's case A: 1,443 `TextAsset` entries, DES-CBC, and **`key == IV ==` an 8-byte constant**
taken from `LuaRuntimeConfig.LuaScriptKey()`. Do not assume every script is encrypted: in that case
`all_lua_files.lua` was plaintext. Decrypt a sample, then prove the output is a script (it parses,
and its first line is plausible Lua) before batch-processing 1,443 files.

Patterns worth recognising without reversing the decryptor:

- **Header-only tamper.** A Lua 5.1 chunk starts with signature `1B 4C 75 61` and version `51`;
  the next byte (offset 5) is the format byte, normally `00`. A build that changes it to `01` makes
  `unluac` say *"non-standard lua format: 1"* while the rest of the file is untouched. Compare the
  first 12 bytes with the standard header before concluding "encrypted".
- **A single-byte XOR tail** with a strongly encrypted head (see §5 for the assembly version). The
  tell is the plaintext zero: deep in the file, the same byte repeats in long runs. One byte of XOR
  turns every plaintext zero into that byte.
- **A "decrypt" that is only a wrapper.** Before implementing a cipher, check whether the transform
  cancels (a repeating XOR with a fixed key, or a stream cipher applied twice). `protocol-reverse.md`
  §7 has the differential probe for classifying a primitive; use it when the shape is not obvious.

### 2.2 Repair the header, then decide what the loader accepts

For the byte-5 tamper, copy the standard 5.1 header over the first 12 bytes, then decompile one file.
If the opcodes were not shuffled, the output is clean source; if the decompiler produces nonsense,
the build may also have shuffled opcodes, which is a different problem.

The other half is the loader: the C# call that loads a chunk often takes a mode/`bytecodeOnly` flag.
If the bundle path loads with `bytecodeOnly == false`, your patch can be **plaintext Lua** — no need
to find a matching 32-bit `luac`. If it is true, recompile the module to the exact Lua version and
ABI, or patch the loader to accept source. Read the call site, do not guess from the file extension.

Batch decompilation is CPU-bound per file (a JVM start per script in the source's toolchain); run it
in parallel and keep the output indexed by entry name, because the next step is a lookup, not a read.

### 2.3 Verify content against entry names

Lua 5.1 bytecode stores its source name immediately after the header (for example
`@UI/reputationshop/shop.lua`). After a batch decompile, compare **the entry name with the chunk
name** before analysing anything. In the source's case, 112 files decompiled to the same unrelated
file because their bundle writer had cloned a template object and `read()` kept returning the
template's bytes. The game itself was fine; only the analysis copy was wrong.

The same warning applies to a hot-update merge: if your bundle wrapper replaces `main.lua` but
`read()` still returns the packaged original, the build patches the **old** script, and the
hot-update version's constants silently disappear. Keep a sidecar map of every byte you write
(replacements and additions) and make your reader return it first; then compare the bytes read back
with the hot-update file before trusting a patch.

## 3. AssetBundle integrity: the CRC is not where you guess

Unity verifies a bundle's CRC when it loads it. The value can live in:

- `<bundle>.manifest` next to the bundle, and
- `assets/AssetBundles/<platform>/AssetDatabase.manifest` (the catalogue).

Guessing which one is live costs a full round. **Run the unmodified build once and read the log** —
Unity prints both values:

```text
E/Unity: CRC Mismatch. Provided d906612, calculated ab764880 from data.
         Will not load AssetBundle 'luascript'
```

Change the manifest the game actually reads (the catalogue in the source's case, not the same-named
bundle manifest) to `0` (skip) or to the computed value. Then verify the bundle loads, not only that
the error disappeared.

**An 8-byte zero prefix is not corruption.** In the source's case A, 2,354 of 2,355 bundles began with
eight `0x00` bytes in the original package; the only exception was the catalogue. All of them loaded.
An earlier pass "repaired" 13 of them and carried the damage into the next baseline. Count the prefix
across the original package before treating it as a fault; skip it on read and preserve it on write.

### 3.1 A bundle whose first block will not decompress

The shape is: a valid `UnityFS` header, the first compressed block fails to decompress, later blocks
are fine. That is a **partial-encryption window**, not a corrupt download. To bound it:

1. Parse the UnityFS header and block table yourself; decompress each block independently and record
   which blocks fail.
2. Entropy-scan the failing block's compressed stream. A sharp drop in entropy marks the end of the
   encrypted window.
3. Run the block's compressor (often LZ4) directly over the ciphertext; the byte offset where it
   crashes is the start of the window.
4. Compare the start/end across several bundles. The source found 1,691 bundles with the same
   `[56:4096]` window, which proves a build-wide scheme rather than per-file damage.
5. XOR two ciphertexts from different bundles: if the transform is a fixed stream cipher, the
   plaintext-derived difference is stable. That tells you the shape, not the key.

Only after this do you know what you are missing: the key or the algorithm. Do not rebuild the
bundles before the window is pinned.

## 4. Rebuilding a bundle without changing it

A bundle is a serialized container, not a zip. Two independent traps:

**The rewriter changes the header/layout.** UnityPy's `save_typetree` can produce a much smaller
serialized file than the original (the source saw 6,700 → 3,552 bytes) because it drops the original
header layout and alignment padding. Compare the object metadata and header of old and new files; if
they differ, pad/restore the original layout before writing the bundle back. For a texture, render the
new text with the game's own font and encode it back to the original format (ETC2 in that case); do
not assume a PNG round-trip is equivalent.

**A stripped resource is still in the dependency graph.** If you remove an AssetBundle but leave the
`AssetBundleManifest` listing it as a dependency of a retained bundle, Unity returns **null** for the
retained bundle. Remove the dependency edges when you remove the assets, not only the files.

**The compressed-size edge case.** A rebuilt bundle can crash where a block's compressed size equals
its raw size — the loader takes a branch that assumes compression. Do not debug this inside a full
build. Replace one hand-made bundle into an existing signed APK, re-align and re-sign, install and
cold-start; each experiment is about a minute. Write a minimal UnityFS reader that lets you change one
block size, one compression flag or one field at a time, and keep a control bundle that differs in
nothing. That is how the source found the exact equality that broke the load.

### 4.1 Adding or replacing a TextAsset

When a Lua script is added to an existing bundle, the writer has to create a new serialized object and
update the container index. Two checks make this safe:

- **Keep the bytes you wrote.** Do not rely on a library's `read()` after `set_raw`/`save_typetree`;
  some versions return the template object or the original bytes. Store the written payload in a
  sidecar map and serve it on read.
- **Verify entry name and chunk name agree**, for every added and every replaced script. Then verify
  the bytes read back equal the source file you intended (especially after merging a hot-update
  layer). A build that patches the old script is indistinguishable from a patch that did nothing.

## 5. Mono assemblies: half-encryption, a rebuilt PE header, and the publisher shell

This is a different shape from a packed dex. The assembly file is present and looks like a PE, but its
first `0x1000` bytes are strongly encrypted and the rest is XORed with one byte. The tell is the same
as §2: deep in the file, one value repeats in long runs, because plaintext zeros became that value.
Autocorrelation does not show a period; the repeated value does.

To read it without reversing the runtime's decryptor:

1. XOR the tail with the single byte.
2. Rebuild the PE header from structural landmarks rather than guessing offsets: the
   `_CorDllMain`/`mscoree.dll` import, the `FF 25 00 20 40 00` entry trampoline, the `.reloc`
   block that points at it, `VS_VERSION_INFO` in `.rsrc`, and the `BSJB` metadata root.
3. Watch for an extra `.sdata` section (static-field initial values): it appears as a hole between
   `.text` and `.rsrc` and as a file offset `0x400` instead of `0x200` for `.text`. Missing it
   makes ILSpy report *"Field data (rva=...) could not be found in any section"*.
4. Accept the boundary: methods whose bodies lived in the first 4 KB are lost (the source counted 87
   small constructors and 123 getters across two assemblies). Static analysis of the rest still works.

**The publisher shell changes the plan.** If `AndroidManifest`'s `application` is a vendor class
(for example a `TPShellApplication`) and `lib/` contains its runtime, the shell checks the APK
(signature/CRC/package) and kills the process about two seconds after launch. The symptom is
`Process ... exited cleanly (4)` with **no Java exception** and no tombstone. Do not read that as a
normal crash. The same shell often decrypts the assembly heads, so removing it also removes the thing
that made the assemblies readable.

The source's route: switch the shell off through its own dex string constants (same-length value
change, then recompute the dex header's SHA-1 and adler32), and recover the plaintext assemblies from
the **original game's process memory** — root, read `/proc/<pid>/maps`, stream anonymous regions,
locate the known XORed body, and restore the DOS header the shell zeroed. That route is specific to
that shell; the general rule is: identify the shell's own kill signal and its own string gate before
patching, and do not ship a rebuild while the shell still owns the process. Shell identification and
the keep/drop decision are in `packers.md` and `code-virtualization-and-custom-linkers.md`;
`advanced-unpacking.md` owns the memory-dump boundary.

## 6. Verification

A Unity asset patch is done when:

- the bundle **loads** (the CRC error is gone, and no null bundle appears in the log);
- the script's **entry name, chunk name and decompiled content** agree;
- a replaced script's bytes read back byte-identical to the source you wrote;
- an added entry exists in the container index and is returned by the loader;
- the on-device screen shows the change, after a cold start, on the same build you installed;
- a control build with **no** patch shows the old behaviour on the same device.

A hash of the APK is not evidence that the bundle inside it changed — check the bundle entry, not the
APK size. Signing and alignment stay in `repack-and-sign.md`.

## 7. Boundary

- **IL2CPP metadata and native code** — `unity-runtime.md` and `il2cpp-protected-metadata.md`.
- **A packer or a self-terminating native check** — `packers.md`,
  `code-virtualization-and-custom-linkers.md`, `native-tamper-and-suicide.md`.
- **Crypto classification** — `protocol-reverse.md` §7; do not implement a cipher from a guess.
- **The game's network layer** — `protocol-reverse.md` and `server-api.md`.
- **Splitting, signing and package rename** — `split-apk.md` and `repack-and-sign.md`.
