# Unity: Mono and IL2CPP, and where the logic actually lives

Load this when the package is Unity — `libunity.so` under `lib/<abi>/`, `assets/bin/Data/` — and the
question is where the game logic is, how to read it, or how to attach a debugger to it.
`framework-runtimes.md` owns *is this even a runtime* and the layer trap; this file owns the two
backends and the tools that turn each one back into readable code. Patching that layer is
`native-and-so.md`; the Android shell around it is `recon.md`.

**Claim strength.** Absorbed from three public write-ups (2026-02 and 2026-06, plus a
dnSpy-Unity-mono build note), not measured here: no Unity package was dumped and no patched Mono
runtime was built in this record. Tool names, paths and the two magic numbers are `unverified`
until you reproduce them; the statements about *which layer owns what* are `inferred` from the same
sources. Steps this file adds as judgement rather than quotation are marked inline.

## 1. Two backends, decided by two files

| What the package ships | Backend | Where the logic is |
|---|---|---|
| `assets/bin/Data/Managed/*.dll` — `Assembly-CSharp.dll` first | **Mono** | CIL in the managed assemblies, JIT-compiled by the Mono VM at run time |
| `lib/<abi>/libil2cpp.so` **and** `assets/bin/Data/Managed/Metadata/global-metadata.dat` | **IL2CPP** | C# compiled to C++ then to native code in the `.so`; names, types and literals survive in the metadata |

`libunity.so` is the engine and is present either way. A Mono build still ships native engine code,
so "there is a big `.so`" proves nothing. On a desktop build the same split appears as
`*_Data/Managed/Assembly-CSharp.dll` versus `GameAssembly.dll` + `*_Data/il2cpp_data/Metadata/global-metadata.dat`.

```bash
unzip -l app.apk | grep -Ei 'Assembly-CSharp|libil2cpp|libunity|global-metadata'
```

Two mis-readings to kill early:

- **"No `Assembly-CSharp.dll`, so the code is stripped or encrypted."** No — that is IL2CPP, the
  normal shipping configuration. The logic is in `libil2cpp.so`; nothing is missing.
- **"The metadata is not at that path, so this build has no metadata."** Older and split packages move
  it; look for `global-metadata.dat` anywhere under `assets/` before concluding anything, and if the
  package is split, check every member (`split-apk.md`).

## 2. Mono: the logic is IL, and IL is readable

`Assembly-CSharp.dll` is the developer's own code. `UnityEngine*.dll`, `mscorlib`, `netstandard` and
the `System.*` family are the framework — worth opening once to learn an API's shape, never the
target of a search. dnSpyEx or ILSpy opens the assembly and decompiles it to C#; search for the
user-visible string first, then `Analyze` on the method that references it for callers and callees.

The only real obstacles at this layer are name obfuscation (locate by string, field shape and
call graph instead) and an `Assembly-CSharp.dll` that will not parse at all (then it is encrypted,
which is a packer problem — `packers.md`).

## 3. Debugging Mono at run time: the stock runtime will not accept the connection

dnSpy's *Unity (connect)* expects to drive the Mono debugger agent through
`--debugger-agent=transport=dt_socket,...` handed to `mono_jit_parse_options`, and it expects
`Debugger.IsAttached` to be truthful. A retail Unity build ships a Mono runtime that carries neither
the dnSpy hook nor a launcher that passes those options, and `defer=y` versus `suspend=n` differs by
Unity version — so the connection is either never accepted or the player sits suspended at startup.
The published route is to build the Unity-flavoured Mono with the dnSpy-Unity-mono changes and swap
`MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll` (back the original up first, then start the game
and use *File → Debug → Unity (connect)*).

The patch is small and each hunk has a purpose worth knowing, because the same hooks are what a
hardened game would detect:

| Change | Effect |
|---|---|
| `ves_icall_System_Diagnostics_Debugger_IsAttached_internal` returns 0 while `dnSpy_hideDebugger` is set | the game's own `Debugger.IsAttached` anti-debug reads "not attached" **while you are attached** — the flag defaults to 1, i.e. hiding is the default |
| `dnSpy_debugger_init()` called from `mini_init`, reading `DNSPY_UNITY_DBG` / `DNSPY_UNITY_DBG2`, else a built-in `--debugger-agent=transport=dt_socket,server=y,address=127.0.0.1:55555,defer=y` | the agent is configured before the VM starts, with no launcher cooperation |
| `dnSpy_debugger_agent_parse_options` accepts a `no-hide-debugger` argument | the opt-out from the lie above, for the case where you *want* the game to see you |
| `mono_debug_init` returns instead of `g_assert(!mono_debug_initialized)` | a second initialisation no longer aborts; the agent and the engine both call it |
| `insert_breakpoint` prefers a sequence point without `MONO_SEQ_POINT_FLAG_NONEMPTY_STACK` | a breakpoint at an IL offset lands somewhere legal instead of being deferred or rejected |
| bdwgc built with `GC_DISABLE_INCREMENTAL` | the incremental collector no longer moves objects under the debugger's feet |
| a dummy `mono_profiler_install` after `debugger_agent_init` | the agent's profiler events are not overwritten by the engine's installer |

Build `libmono-dynamic` Release/x64 from `msvc/mono.sln`. The write-up's own trap: linking fails
until the new `dnSpy.c` is compiled by hand first, because the project file has not picked it up yet.

Two boundaries. A prebuilt `mono-2.0-bdwgc.dll` for one Unity version circulates with that write-up —
that is a third-party binary, so audit it before use (`third-party-builds.md`). And on Android the
equivalent artifact is `lib/<abi>/libmono.so` (*inferred* — the source is desktop-only); replacing it
changes the APK, so it is a repack with all of a repack's obligations (`repack-and-sign.md`,
`signature-derived-keys.md`).

## 4. IL2CPP: native code plus a metadata table

`libil2cpp.so` is the whole of the C# code, ahead-of-time compiled, with no IL and no names. The
names, namespaces, field and method signatures, type relationships and string literals live in
`global-metadata.dat`. The pair is the unit of work: the `.so` is unreadable without the metadata, and
the metadata alone gives you a class list with no addresses.

Both files also tell you whether they are plain, in one line each — and getting this wrong is the most
expensive mis-diagnosis at this layer, because "no symbols" and "encrypted symbols" look identical in
a decompiler:

```bash
xxd -l 16 lib/arm64-v8a/libil2cpp.so                             # 7f 45 4c 46  (ELF)
xxd -l 16 assets/bin/Data/Managed/Metadata/global-metadata.dat   # af 1b b1 fa  (0xFAB11BAF)
```

### Il2CppDumper, and the order of the IDA import

```bash
Il2CppDumper libil2cpp.so global-metadata.dat out/
```

On a desktop build pass `GameAssembly.dll` in place of `libil2cpp.so`. The outputs that matter:

| Output | Use |
|---|---|
| `DummyDll/` (and `dump.cs`) | the recovered class / method / field *outline* — open in ILSpy or dnSpy to navigate; bodies are absent by construction |
| `il2cpp.h` | structs for the decompiler, so IL2CPP objects stop looking like `void*` |
| `script.json` | method → address, the table that names functions in IDA or Ghidra |
| `stringliteral.json` | literal → address, the table that names string data |
| `ida_py3.py` / `ida_with_struct_py3.py` (or `ghidra.py`) | the importers |

The import order is not cosmetic: each script decorates what the previous one produced, so running
them out of order **succeeds** and leaves a half-named database. In IDA, File → Script file, in this
order:

1. `ida_py3.py`
2. `script.json`
3. `stringliteral.json`
4. `ida_with_struct_py3.py`, answering `script.json` then `il2cpp.h`

Then analyse from a named function, not from the string blob. Cpp2IL is the alternative front end
(`Cpp2IL --help`, then `--game-path <dir> --output-to <dir>`); when two dumpers disagree about the
same binary, the disagreement is a claim about your toolchain until a reproducible run settles it —
the same rule as `pitfalls.md` P47.

### When the metadata does not parse

- **Encrypted metadata** (`xxd` shows the wrong magic): dump at run time with Zygisk-Il2CppDumper, or
  recover the loader's decryption (`packers.md`). A static dumper will never succeed here, and retrying
  with another one is the wrong move.
- **Version newer than the dumper**: pin the dumper to the Unity version. A dump from the wrong version
  produces plausible names with wrong struct offsets, so treat every field offset as suspect until one
  is confirmed at run time.
- **Names still missing after a successful dump**: check you are looking at the module the process
  actually loads — a split or stubbed `libil2cpp.so` inside the APK is not necessarily the one mapped
  (`native-and-so.md`).

## 5. Driving IL2CPP at run time: frida-il2cpp-bridge

When the dump is encrypted or the question is behavioural, the bridge resolves classes by name at run
time through the exported il2cpp API. Trace a class:

```ts
import "frida-il2cpp-bridge";
Il2Cpp.perform(() => {
    const image = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const cls = image.class("Assets.Scripts.AndroidKit");
    Il2Cpp.trace(true).classes(cls).and().attach();
});
```

or one method, with `Il2Cpp.trace(true).methods(cls.method("SetShield")).and().attach()`. Run it with
`frida -U -f <pkg> -l frida.js`, and `Il2Cpp.dump()` writes a metadata dump from the live process —
the usual answer to an encrypted `global-metadata.dat`. Il2CppHookScripts (`il2cpp-hooker`) is a
scripted alternative with the same dependency.

The dependency is the boundary: a build that hides or strips the il2cpp exports breaks the bridge, and
the failure presents as *class not found* — indistinguishable from a wrong class name. Confirm the
exports exist before believing a negative lookup.

## 6. When the deliverable is an audit rather than a patch

The same artifacts answer "what does this package leak", which is often the actual request. One probe
per question:

| Question | Probe |
|---|---|
| Is this a development build? | `android:debuggable` in the manifest; `Development Build` / script-debugging strings; the `Unity` logcat tag |
| Do test endpoints or secrets ship in the code? | `strings -a libil2cpp.so \| rg -i 'secret\|token\|password\|gm\|cheat\|test-api'`, the same over `global-metadata.dat`, and `rg` over `dump.cs` / `DummyDll` |
| Are unshipped assets in the package? | AssetStudio or AssetRipper over `assets/bin/Data`: `TextAsset` configs, `Texture2D`, `AudioClip`, `AssetBundle` names |
| Does the Android shell leak? | jadx for hardcoded SDK keys, permissions, exported components; `apktool d` for the manifest |
| Is the client authoritative for currency, drops or purchases? | proxy and replay (`protocol-reverse.md`): a client-supplied value the server never recomputes is the finding, and no client-side change fixes it (`server-api.md`) |

Report one finding per row with the probe, the file and the offset or line, and a boundary sentence
saying which versions it was observed on. "The package contains X" and "the server trusts X" are
different findings with different owners.

## 7. Boundary

Nothing here was exercised in this record. The steps that would make it `observed`: dump a known
Unity package with Il2CppDumper, re-import into IDA in the order above, and set a breakpoint that
hits at a named method; separately, build the Mono patch and hit a breakpoint in dnSpy. Until then,
treat the tool output as a map that still needs one verified landmark. For a target that fights the
debugger, `detection-and-anti-analysis.md` owns the triage — and `ida-so-debugging.md` owns the
attach mechanics for the underlying `.so`.
