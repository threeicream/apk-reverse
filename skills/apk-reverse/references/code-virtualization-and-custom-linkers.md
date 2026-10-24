# Code Virtualization & Custom Linkers

Load this when recon says **there is no packer** (the manifest's `application` is the app's own
class, dex is readable) and yet a re-signed build dies before your code runs — especially when the
death is `SIGSEGV fault addr 0x0` with all registers zero.

This is the layer between "packed" and "clean". `packers.md` covers a shell that owns
`Application`; this file covers protection that leaves `Application` alone and instead
**turns individual methods into native code** and hosts a private loader next to them. It is now
common enough that treating it as "no packer, therefore easy" is the most expensive recon error
in this skill's history.

## Identification — three cheap tells

1. **Whole classes whose methods are `native` declarations with no implementation.**
   Read the smali for the entry Activity / engine host class. Under code virtualization the
   *entire class* is converted — lifecycle callbacks, getters, everything — each becoming a bare
   `.method public native ...` with no body. A framework class you *know* ships a Java
   implementation (a Flutter/Unity/RN host class is the usual victim) sitting there fully
   `native` is the signal.

   Two `native` methods is normal (JNI). **Sixty is virtualization.**

2. **A registration call in the class's static initializer.** Someone binds those native
   declarations to an implementation at class-load time:

   ```
   .method static constructor <clinit>()V
       invoke-static {v0, v1}, L<somewhere>/DtcLoader;->registerNativesForClass(ILjava/lang/Class;)V
       invoke-static {v1},     L<somewhere>/hidden/Hidden0;->special_clinit_0_00(Ljava/lang/Class;)V
   ```

   The `Hidden0.special_clinit_*` family is the virtualizer's hook for running its own version of
   the class initializer. When you see this, the Java in that class **is not what executes**.

3. **A shipping library whose SONAME does not match its filename.** A private loader is often
   named for its role while sitting under an innocuous filename. Read `DT_SONAME` from
   `.dynamic`, not the file name — `probe_deps`-style parsing of `PT_DYNAMIC` (see
   `native-tamper-and-suicide.md` §Forged section headers) gives you the truth. A `lib<something>.so` claiming
   `soname = liblinkerloader.so` is a private ELF loader.

Supporting tells: `assets/` carrying a small text descriptor naming the protector and its version;
native libraries woven into `DT_NEEDED` chains of other libraries (the virtualized code has to be
reachable); log lines tagged with the loader's own name appearing during startup.

## The deadlock that eats hours — and the way out

A virtualizer that also does integrity checking produces this shape:

| Action | Result |
|---|---|
| Keep the private loader in the APK | its embedded validation runs → deliberate crash on a re-signed build |
| Delete the private loader | the virtualized class has **no implementation at all** → `UnsatisfiedLinkError: dlopen failed: library "…" not found` |

Both routes die, and the two failures look nothing alike, so it is easy to conclude the target is
impossible. It is not. The way out is one question:

> **Is that library the checker, or the implementation — and who asks for it?**

## Separate the checker from the implementation

Two distinct roles hide behind "a protected library":

- **The implementation** — the native code that *is* the virtualized class. It must be present and
  loaded, or the class cannot work.
- **The checker** — a validation payload (a signature/integrity payload, a second-stage
  self-decrypting image) that something *explicitly loads*.

They are frequently **different libraries**, and the load of the checker is frequently a
**single, findable call site** — not a link-time dependency.

Test which is which before designing a fix:

```
# 1. Does anything name it in DT_NEEDED?  Parse PT_DYNAMIC of every shipped .so.
#    No DT_NEEDED referrer  =>  it is dlopen()ed, i.e. named at some call site.
# 2. Delete it and read the exact error: which class/method was executing when the
#    load failed?  That is the caller.
```

In the observed case the error was not "the class is missing" but:

```
java.lang.UnsatisfiedLinkError: dlopen failed: library "lib<checker>.so" not found
    at java.lang.System.loadLibrary(System.java)
    at <framework host class>.onCreate(Native Method)
```

Read that stack carefully: the **virtualized** `onCreate` — the very code you feared deleting the
library would break — is running fine. It is the *checker* that is absent. The implementation lives
elsewhere and was never the problem.

**That single stack frame converts an impossible target into a trivial one.**

## Technique: redirect the load by rewriting a string constant

Once you know the checker is named at a call site, you do not need to patch code, hook anything, or
neutralize a crash. **Change what that call site loads.**

JNI-heavy native code keeps its class/method/string operands in a constant pool inside the library.
A `loadLibrary("X")` becomes three facts sitting in `.rodata`/`.data`:

```
…  onCreate  (Landroid/os/Bundle;)V  loadLibrary  (Ljava/lang/String;)Ljava/lang/String;  …
…  <SomeUnrelatedClassName>  X  <unrelated constant>  …
```

Find the name as an **isolated NUL-terminated string** and rewrite it **in place, same length** to
the name of a library that is *guaranteed already loaded*. On Android, `android` (`libandroid.so`)
is reliably mapped — the protected libraries themselves depend on it.

```
apkhuan -> android      (7 chars -> 7 chars)
```

Why this is disproportionately effective:

- **Equal length means zero structural change.** No offsets move, no section resizes, the ELF stays
  exactly as valid as it was. Nothing for an integrity check to notice about *layout*.
- **The load succeeds**, so no `UnsatisfiedLinkError` and no error branch anywhere.
- **The checker never gets mapped**, so none of its validation runs — the signature payload, the
  deliberate-crash payload, all of it becomes dead weight in the APK.
- **You never patch a death path**, so the whole `native-tamper-and-suicide.md` rule set (make it
  *return*, don't make it *not return*) never comes into play. There is nothing to neutralize.

Requirements and hazards:

1. **Same byte length is not optional.** Replacing with a shorter/longer name shifts everything
   after it. Pad only within the same NUL-terminated slot; never spill into the next constant.
2. **Verify the string is an isolated constant** — the byte before and after must be `\x00`.
   A substring of a longer identifier will corrupt that identifier.
3. **The replacement must be loadable and already-loaded.** A nonexistent name throws and puts you
   back in the deadlock; a heavy library changes startup cost.
4. **Scan the whole file** for the name, then confirm which occurrence sits in the constant pool.
   Report the offset in the patch record.

`scripts/so_constpatch.py` implements this: finds isolated constants, enforces equal length, writes
a patched copy, and prints the byte-diff.

This is one member of a general family — **redirect a reference instead of defeating a check** —
and the same shape recurs for class names, method names and file paths in a constant pool.

## Expected log shapes

A private loader announces itself. These strings come from the loader, not from the app, and their
presence/absence across builds is a usable signal:

```
I/<Loader>: Loading embedded protected image from carrier (self)
I/<Loader>: Found embedded protected image at offset 0x…, logical size 0x…
E/<Loader>: Invalid ELF magic                          <-- appears ONLY on a modified build
D/<Loader>: ELF Header: type=3, machine=183, entry=0x0, phnum=N
D/<Loader>: Starting PrelinkImage for embedded_protected
```

A custom container magic at the tail of the library (a four-byte tag, not `\x7fELF`) marks the
embedded image; `entry=0x0` plus `SIGSEGV fault addr 0x0` is the loader failing to decrypt its
payload and jumping to a zero entry. Treat "`Invalid ELF magic` appears on my build and not on the
original" as **proof the loader is validating the build**, which is exactly what makes the
string-redirect route worth trying.

When the loader itself becomes the object of study — you need to load, dump or repair its payload
rather than neutralise its check — `linker-and-soinfo-repair.md` owns the pipeline arithmetic and
the `soinfo` hand-off; this file owns recognising that the loader is present and deciding whether
to keep it.

## Staged loaders that decrypt a DEX from assets

A second family does not keep the payload in the APK's dex at all. Recognise it by the *shape*, not
by a product name:

1. A Java `Application`/`attachBaseContext` loads a small stage-1 `.so`.
2. That library's `JNI_OnLoad` calls `RegisterNatives` for two or three methods and returns.
3. `attachBaseContext` then calls one of them with `dataDir`, `nativeLibraryDir` and the
   `AssetManager` — the arguments are the tell that the native side is about to write a file and
   load code from it.
4. The native method opens an asset whose name looks random, derives a key, decrypts an AES payload
   into Dalvik bytecode, and returns a direct `ByteBuffer`.
5. Java passes that buffer to a `DexClassLoader`/`loadDex` path. The stage-1 `.so` may then launch a
   stage-2 `.so` from the decrypted code.

The stage-2 payload often lives in `assets` as an extensionless `.sec` file. One sample selected it
by CPU family — including mapping **ARM64 to an `x64`-named payload** — then:

- hex-decoded a constant string into an AES-256 key and a per-block IV;
- decrypted 16-byte blocks with AES, then XORed each with the IV;
- read an **8-byte tail** from the `.sec` file as an offset, copied `[offset, EOF)` as the real
  payload, and XORed that region with the file's own prefix;
- decrypted the exported symbol name with the same construction before `dlsym`, and `unlink`ed the
  temporary file after `dlopen`.

**What generalises:** the asset name, key, IV and tail layout are per-build and must be read from
the loader, not carried across. What does carry is the diagnostic chain — *asset with a random name +
`AssetManager` passed into a registered native method + a returned direct buffer + `DexClassLoader`*
— and the fact that the second stage picks its payload by ABI, so an x86 host may never see the
ARM64 branch.

**Preconditions to record before spending time:** whether the loader writes to `dataDir` or
`nativeLibraryDir`, whether the payload is deleted after load, and which ABI the running process
reports. A dump taken after the `unlink` can only come from memory; a dump taken before it can come
from the file, which is cheaper and gives an exact length.

**Claim strength.** One family, one sample, absorbed from a public write-up; keys and offsets are
deliberately not reproduced. Treat the sequence as a recognition template and recover the constants
from the binary in front of you.

## What the native check actually reads — measure it, don't guess

A validation payload that reads "the signature" can be reading several different things, and the
answer decides whether *any* repack route exists:

| It reads | Consequence |
|---|---|
| the certificate material **inside the APK** | keeping the original signature block while swapping code can pass |
| the signature **PackageManager reports** | that trick fails; you must remove the check (this file's technique) or rebuild |
| an entry **hash** of the whole file | only the string-redirect / check-removal route survives |

**Single-variable experiment to tell them apart.** Same APK content both times; flip only the
PMS-recorded signature:

1. Install a build **you signed** normally, so PMS records *your* certificate.
2. Root-overwrite that installed `base.apk` with your candidate (one whose *internal* signature
   block is the original), leaving PMS's record untouched.
3. Launch.

Dies ⇒ the check reads the PMS-reported signature, and preserving in-APK certificate material
cannot save you. Survives ⇒ it reads in-APK material, and a "keep the original signature block"
route is worth investing in.

Do this **before** investing in elaborate signature-block plumbing. It is two installs.

## A Java-layer "signature killer" is a decoy

A protection bundle may ship a Java class that hooks `PackageManager` so the framework reports a
hardcoded certificate, and log `Signature consistency ok` forever — including on your modified
build. This is an **anti-tamper feature aimed at other patchers**, not a gate you must satisfy.

Its corollary is what matters operationally: **`Signature consistency ok` in the log proves
nothing.** Do not let a green Java-layer message talk you out of the fact that the process is
dying, or send you hunting for a Java signature check. If the death is `SIGSEGV` with a zero
program counter, the check that killed you is native and the Java one is irrelevant.

Two practical notes:

- **Do not delete such a class to "clean up".** It usually participates in the `Application`
  inheritance chain; removing it breaks startup and trips unrelated class-hierarchy checks.
- Its presence is a strong hint that **the code that matters is virtualized**, because it exists to
  survive exactly the kind of repack you are attempting.

## Verification

A string-redirect fix is verified by the **absence of the loader**, not by the absence of an error:

1. Loader's log tag count in a full cold-start capture = **0** (previously non-zero).
2. `Invalid ELF magic` = 0.
3. `SIGSEGV` = 0 **and** `SIGSYS`/seccomp kills = 0 — the secondary kill paths the payload carried
   disappear with it. A drop from 1 to 0 here is a real result worth recording.
4. Process survives past the previously measured time-to-death, on this machine, with nothing
   attached; then survives real interaction.
5. The features that class implements still work — the virtualized code is the *implementation*, so
   exercise it (start playback, navigate, whatever it owns). A build that starts but whose
   virtualized feature is dead is not a result.

Record the original and patched bytes, the offset, and the loader log counts before/after in the
patch record — the same audit standard as any other byte-level edit.
