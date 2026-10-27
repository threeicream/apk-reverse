# Attaching a real debugger: IDA's remote server, and the handshake that releases the app

Load this when Frida is the wrong instrument — you need to single-step, read registers at a fault, or
set a breakpoint inside a `.so` and inspect the stack — and the target is debuggable or you can make
it so. `dynamic-frida.md` owns hooking; `hardware-watchpoints.md` owns observation with no debugger
attached at all; this file owns the debug-server route and the two preconditions that decide whether
it works.

**Claim strength.** Absorbed from three public walkthroughs (2024-07, plus a MuMu-emulator note and
a 2026 Unity session), all against CTF apps that were already debuggable, and none reproduced here.
The debugger-side signal policy in §8 is one source's account, `unverified`. Commands on which the
sources agree are stated plainly; the single-source details are marked *unverified*; anything this file adds
as judgement is marked *inferred*.

## 1. Two manifest facts decide everything

- **`android:debuggable="true"`** — without it the app cannot be started in wait-for-debugger mode and
  `run-as` does not exist. A retail build needs a repack (`repack-and-sign.md`) or a
  `ro.debuggable` override on a rooted ROM (`magisk resetprop ro.debuggable 1`, then `stop; start`).
  The override is **global and persistent** — every app on the device becomes debuggable — so it is a
  fallback for your own analysis device, never part of a deliverable.
- **`android:extractNativeLibs="true"`** — this one is not about permissions. It decides whether the
  `.so` exists as a file on disk, which is what a debugger needs; §5 below is the failure it causes.

Read them from `apktool d` → `AndroidManifest.xml`, or `aapt dump xmltree app.apk AndroidManifest.xml`.
On a split package check the base member, not the last file you opened (`split-apk.md`).

## 2. Match the server to the ABI that is actually loaded

IDA ships one debug server per ABI under `dbgsrv/`. The library's directory decides which: a target in
`lib/arm64-v8a/` wants the arm64 server, one in `lib/x86_64/` wants the x86-64 server. A mismatch is
reported **when the server starts** ("expected X but Y"), not when you attach — so read the server's
first line instead of interpreting a silent attach later.

```bash
adb push <ida>/dbgsrv/android_x64_server /data/local/tmp/android_x64_server
adb shell
su
chmod 755 /data/local/tmp/android_x64_server
```

The write-up uses `777`; `755` is sufficient when the file is owned by the shell user and the server runs
as root (*inferred*). Two mechanical traps it records: `\` and `/` are not interchangeable in the push
path, and the file keeps the name you gave it on the destination side — the later
`./<name>` must match that, not the source filename. `/data/local/tmp` is the only location an
unprivileged `adb push` can write and a root shell can execute without SELinux complaints on most
builds.

## 3. Run it as root, forward the port, and leave it running

```bash
adb forward tcp:23946 tcp:23946      # IDA's default debug-server port
/data/local/tmp/android_x64_server   # in the root shell from §2
```

Start the server **as uid 0**. A server running as the shell user can only see its own processes, so
the target is simply absent from IDA's attach list — the recorded symptom is "the list is empty or has
one entry that is not the app". Keep that terminal open: killing it detaches every session.

## 4. Start paused, then release the app

```bash
adb shell am start -D -n <pkg>/.MainActivity
```

`-D` starts the process **suspended, waiting for a debugger**. Attaching from IDA alone does not
resolve that wait, because what the process is waiting for is the *JDWP* handshake, not the remote
debug server. That is why the app appears frozen and why breakpoints "never fire": no code is
executing yet. Forward a second port and connect the JDWP client:

```bash
adb shell ps | grep <pkg>            # or: adb jdwp   /   frida-ps -U
adb forward tcp:8700 jdwp:<pid>
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700
```

Use a high port (the write-ups recommend 5000–10000) so it does not collide with 23946, and use the
pid of the **app** process, not of the debug server. IDA → Debugger → Attach to process now, with the
remote host set to `127.0.0.1` and port `23946`. Suspending on process entry, on thread start/exit and
on library load/unload is worth enabling before the first run: without it, an early breakpoint in a
library constructor is already behind you when the process stops.

## 5. "The breakpoint will not bind": the `.so` was never extracted

**Symptom.** The process runs, IDA lists and attaches to it, the module list has no `libtarget.so`, and
every breakpoint set in it is refused or never hits. Nothing in logcat. The library is plainly loaded —
the feature it implements works.

**Root cause.** `android:extractNativeLibs="false"` means installation leaves the library inside
`base.apk` and the loader maps it from there. There is no
`/data/app/<pkg>-<hash>/lib/<abi>/libtarget.so` for the debugger to name, so breakpoint resolution has
nothing to bind to. `pm path <pkg>` names the APK's directory; `ls` beside it finds no `lib/` at all.
The mapped region is backed by the APK, which is the same shape as the "an `r--s` view of `base.apk`
looks like a dex" case in `advanced-unpacking.md` — the file on disk is not the thing in memory.

**Two fixes.**

1. Repack with `android:extractNativeLibs="true"`. The install then lays the libraries out under
   `lib/<abi>/`, and every debugger names them normally. It changes the signing certificate, so a
   signature check turns this into the `signature-derived-keys.md` problem.
2. Keep the original package and give the loader the on-disk copy it prefers. `pm path <pkg>` to find
   the install directory, then push the matching `.so` into
   `/data/app/<pkg>-<hash>/lib/<abi>/` as root (create the directory if absent). The recorded result is
   that the app then loads the file instead of the in-APK copy. Whether a *hardened* build still
   prefers it, and whether its own integrity check notices the extra file, is *unverified* — verify
   both before building a plan on it.

**What not to do.** Pointing IDA at the `.so` extracted from the APK and calling that "the module" is
the trap that wastes the session: the addresses in that file are the ones the process never mapped, so
a breakpoint that *does* set lands on a copy of the code rather than the code.

## 6. Prove the channel before blaming the target

Set one breakpoint in a library that certainly executes early — `libc`'s `open`, the ART loader — and
resume. If it hits, the channel is good and a non-hitting breakpoint in the target is about the target
(never loaded, different copy, inlined, or anti-debug). If it does not hit, the fault is in setup:
server uid, ABI mismatch, or a JDWP wait that was never released. This is the same control-run
discipline as `long-task-discipline.md` §single-variable discipline, applied to the debugger itself.

## 7. What this route cannot hide

- `TracerPid` in `/proc/self/status` is non-zero for as long as you are attached, so any check that
  reads it sees you (`detection-and-anti-analysis.md`).
- The server binary is a file with a known name in `/data/local/tmp`, and a process whose parent is a
  root shell is visible in `ps`.
- Software breakpoints are written into executable pages; a checksum over a mapped library catches them
  (`byte-level-patching.md`). For observation with no writes, use `hardware-watchpoints.md`.
- `am start -D` is visible to the platform and puts the process in a debuggable state that the app can
  query, so "the app behaves differently only while I debug it" is a real observation, not a mistake.

## 8. Stops that are the debugger's, not the target's

Most "the target crashed" observations in a debug session are properties of the debugger's own
settings. Three that cost a whole session:

- **A platform signal is not target logic.** A Unity-backed app under IDA repeatedly stops on
  `SIGPWR`/`SIGXCPU`-class signals it never handles, because the platform raises them and the app
  ignores them. With the default *suspend on this signal* the pause **is** the crash: the process is
  stopped somewhere it cannot make progress, the watchdog or runtime aborts, and the abort takes IDA
  down with it. Set those signals to *pass to application* (report on log or silent). After that the
  same signal costs a log line instead of a session, and the only thing that changed was your
  debugger.
- **One database per activity.** Attaching and detaching from the database you used for static
  analysis tends to hang on exit or leave it unusable — and the annotations are the expensive part.
  Copy the database (or keep a separate debug-only one) and leave the static one read-only.
- **Interacting with a paused process is input injection.** Clicking around the app while it is
  stopped delivers real input into the frozen process and reproduces the same hang/crash class.
  Resume, then interact; do not "help" a suspended app.

Nothing here is about anti-debug: if the process dies while it is *stopped*, suspect the debugger's
signal policy before suspecting the target.

## 9. Boundary

All three sources are emulator or AVD walkthroughs on CTF apps with `debuggable` already set; none
exercised a hardened target, and this record did not run the route at all. `unverified`: the exact
`dbgsrv` filenames per IDA release, the `chmod` mode, the debugger menu labels across 7.x and 8.x, and
whether an on-disk `.so` outranks the in-APK copy on a hardened build. What would make the route
`observed`: one breakpoint hit and one register read at a known function, on a package whose only
modification is the manifest.
