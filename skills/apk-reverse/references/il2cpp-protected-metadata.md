# IL2CPP when the metadata is not a readable file

Load this when a Unity package is IL2CPP but the usual pair is not usable: `global-metadata.dat` is
0 bytes, absent, has the wrong magic, carries a custom container, or Il2CppDumper rejects the
`libil2cpp.so` it came with. This file owns getting *a* parseable metadata image and *a* dumpable
`.so`; `unity-runtime.md` owns backend identification, the normal dump, the IDA import order and
the runtime bridge. Load that first if the pair is plainly readable.

**Claim strength.** Absorbed from eight public write-ups (2024-2026) and not reproduced here: no
Unity package was decrypted, dumped or re-imported in this record. Every offset, magic value and
tool behaviour below is `unverified` until you reproduce it on your sample; the *ordering rules*
(which anchor to read, which layer to attack, what a failure means) are `inferred` from those
sources. Nothing here is a measurement. Where a number identifies one sample rather than a format,
the text says "one sample" and you must not carry it to another build.

## 1. Triage: four shapes that all look like "encrypted metadata"

Before choosing a route, decide which shape you have. They need different work, and retrying the
same dumper is the wrong response to three of the four.

| Observation | Shape | First move |
|---|---|---|
| File is 0 bytes, or absent, while the game clearly runs | metadata is supplied from memory, a PE resource, or an appended blob | find the consumer, read its output pointer (§2) |
| File exists, `xxd -l 4` is not `af 1b b1 fa` | encrypted or wrapped container | identify the cipher shape (§3) |
| Magic is right, but the dumper reports a version and then produces garbage fields | version field lies, or the layout is spliced | treat the version as a claim, validate the struct (§5) |
| `libil2cpp.so` is present, but every registration search returns 0 | protected/repacked `.so`, or the wrong module is mapped | dump the live image (§4) |

Two cheap checks come before any reverse engineering:

```bash
xxd -l 16 assets/bin/Data/Managed/Metadata/global-metadata.dat   # 0xFAB11BAF
xxd -l 16 lib/arm64-v8a/libil2cpp.so                             # 7f 45 4c 46
```

A correct magic proves the first 4 bytes only. A file can pass that check and still carry an
encrypted string blob, a wrong header size field, or a custom program table (§3, §5). Conversely,
a zeroed magic does not prove the file is encrypted: one shipping build wipes magic and version and
embeds the metadata in the `.so` with the rest of the header intact.

**A 0-byte metadata file is a positive finding, not a missing file.** It means the build does not
use the file at all, so a static decryptor has nothing to decrypt. Look for the loader's output.

### 1.1 A rebuilt `libil2cpp` announces itself in the ELF tables

One build's own triage script flags three things before it parses anything: a `JNI_OnLoad` export, a
`DT_INIT`/`init_array` of the library's own, and an `SHT_LOUSER` section. None of the three is
something the engine's build path needs, so any of them is a candidate added step — read them as
heuristics, where a false positive costs one `readelf`:

```bash
readelf -sW libil2cpp.so | grep -i jnionload
readelf -dW libil2cpp.so | grep -Ei 'INIT|FINI'
readelf -SW libil2cpp.so | grep -w LOUSER   # a section type, not a name
```

`JNI_OnLoad` means the library wants a JVM-side entry point, which is a JNI-sinking or loader shape
rather than something the engine itself calls through. An own `DT_INIT`/`init_array` is the earliest
place arbitrary code can run. `SHT_LOUSER` is a section the
linker reserves for the application — a convenient place to park a payload, and a common marker in
this family. Read these tables **before** hunting ciphertext: the injected entry is where metadata and
code are decrypted, and it is also what a dumper's "this file may be protected" refusal is reacting to.
Then continue at §2 and anchor on the consumer rather than the file.

## 2. Anchor on the consumer, not the path

The reliable address is the pointer *after* decryption and de-obfuscation. Two anchors exist, and
they are not interchangeable:

- `il2cpp::vm::MetadataLoader::LoadMetadataFile` — the function that returns the metadata base.
  Its return value (or the global it stores into) is the plaintext image.
- `il2cpp::GlobalMetadata::Initialize` — a second entry point some builds use for a custom
  decrypt-and-validate step. One write-up wasted a diffing pass inside `LoadMetadataFile` before
  finding the cipher in `GlobalMetadata::Initialize`.
- `il2cpp::utils::MemoryMappedFile::Map` — the file-mapping layer. A `jmp` from here into a
  non-standard section is a signal that the mapping was replaced by a custom loader.

Procedure:

1. Find the metadata path string (`global-metadata.dat`) and its xrefs. The consumer is usually
   one or two calls away.
2. Diff the function against the matching upstream `libil2cpp` source tag. A short added loop over
   the mapped buffer is the decryption, stated in the open.
3. Hook the *return* of the loader, or read the global it writes after the call. Do not hook the
   `open`/`mmap` path: that is the ciphertext.
4. Dump `[base, base + size)` using the size rule in §2.1 rather than a guessed length.

### 2.1 Sizing a header whose fields you do not trust

The metadata header is an array of 64 `int32` values. For a version whose tail counts are unknown,
walk backwards from `0x10C` in steps of 8:

```text
i = 0x10C
count  = read_i32(base + i)
offset = read_i32(base + i - 4)
if count != 0: size = offset + count; stop
i -= 8
```

This works when magic and version are zeroed, and it survives a version mismatch because it uses
only offset/count pairs that are still laid out in the same order. (`observed`, host: on a synthetic
header whose magic and version are zeroed and whose tail counts are zero, the walk returns the true
length `0x1140` while a fixed mid-header pair returns `0x1098`; see
`docs/tool-verification/fixtures/verify_ref_claims_10c.py`.) Bound the loop (for example
`i > 0`), wrap reads in the platform's fault handler on Windows, and treat a non-monotone result as
"this is not the header you think it is", not as a size.

### 2.2 Metadata outside the filesystem

Three placements recur:

- **PE resource, located by a hashed logical name.** One loader hashes the requested name with two
  accumulators (an FNV-1a-style `hash *= 0x1000193; hash ^= byte` and a roll
  `hash = hash*0x83 + byte`), combines them into a 64-bit key, and compares against constants that
  map to a resource id. It then calls `FindResourceA(hModule, id, "CFG")`, `SizeofResource`,
  `LoadResource`, `LockResource`. The hash table is small and reimplementable offline with
  `pefile`; once the resource is extracted, the container cipher decides the next step.
- **Appended or embedded in `libil2cpp.so`.** No separate file, and no section name that announces
  itself. Find the offset from the loader's pointer arithmetic, then cut the blob from the mapped
  image rather than from the file if the loader applies a relocation-relative offset.
- **A non-standard section reached by a `jmp`.** The entry stub replaces the mapping function; the
  payload lives in a section whose name is product-specific. Treat it as a custom container, not as
  ELF data, and use the loader's own parse order.

## 3. Container and cipher shapes worth trying first

Do not begin by assuming AES. Public Unity protections in this set are dominated by cheap,
self-describing transforms, and each has a diagnostic that distinguishes it from "real crypto".

### 3.1 Whole-file repeating-key XOR

The most common shape: after the mapping call, a loop does

```c
for (i = 0; i < mapped_size; i++)
    mapped[i] ^= key[i & 0x7F];       // 128-byte table, index masked
```

Look for `^=` on the mapped buffer in the loader diff. The key is often a fixed byte table in
`.rodata`, not a derived secret. Extraction is mechanical: copy the table, apply it to the file,
check for `0xFAB11BAF`. If the file grows by a few bytes between versions, do not assume the same
key or the same offset; re-diff.

### 3.2 Custom magic plus a bytecode VM

One family wraps the header in a container with its own magic (`0x1357FEDA` in one sample) and a
program table, then runs a 255-case `switch` over the body. Each case computes an index into the
destination and applies one of: XOR with an immediate, add, subtract, byte swap, or rotate by a
key byte masked with 7. The layout in that sample was: magic at 0, length at 4, header at 8,
program at `0x108` (64 bytes), data at `0x148`, and the plaintext began 8 bytes into the
decrypted region.

The generalisable part is not the opcode set; it is that **the VM is a dispatcher over a
self-describing container**. Dump the program table, name each case by its effect, and replay the
program in Python. Do not single-step the VM instruction by instruction in a debugger; the table
is the specification.

**Read the call site before replaying, because the schedule decides what a unit test is.** One build
runs the interpreter once per fixed-size block — `apply(program, 0x40, table, out + i, min(0x40,
remaining))` in a loop — with the same constant table re-passed on every call and no state carried
between them. That makes one block a complete test: decrypt block 0, check the result against the
plaintext you already know it must contain (a magic, or the first string), and only then run the rest.
If the call site instead updates a context between iterations, the blocks are chained: no per-block
shortcut exists, replay must start at 0, and a mismatch at block 7 is a key/program error you cannot
localise by looking at block 7. The truncated tail is also worth reading explicitly, because a tail
handled as a full block shifts everything after the last boundary.

### 3.3 XXTEA with a length word

A resource-container sample used XXTEA: `delta = 0x9E3779B9`, `rounds = 6 + 52/n`, decrypt from
the tail, key a short ASCII string zero-padded to 16 bytes. The plaintext length was stored in the
**last 32-bit word** and accepted only when it fell in `[total-7, total-4]`. Check that range before
trusting a decrypted buffer; a wrong key usually fails it.

### 3.4 Length-derived string ciphers

String literals are often encrypted separately from the header (and may be the only encrypted
region). Two shapes recur:

- A single-byte key derived from the literal length, for example `key = length ^ 0x2E` applied to
  every byte. Long literals may use a vectorised bulk path and short ones a scalar path; both must
  produce the same byte-wise result.
- A key derived from counters that are recoverable from the method body, such as
  `ilLength * exceptionClauseCount * localVarCount` duplicated into a 64-bit value and rendered as
  a decimal string. This appeared in a HybridCLR Interpreter build.

Try length-derived key material before attacking the cipher. It is cheap, and it explains why a
generic XOR brute force finds nothing.

## 4. A live image is the fallback, and it is usually cheaper

When the metadata and the `.so` are both protected per version, reimplementing the loader is more
work than dumping the process. The constraint is that the dump must be *the image the process
mapped*, not the file on disk.

1. Read `/proc/<pid>/maps` and take the **second** mapping of `libil2cpp.so`. The first is the
   file-backed, still-encrypted view; the second is the anonymous/decrypted image. Dumping the
   first produces a file that looks plausible and fails every registration search.
2. Record the mapping base. Dump the whole mapping to a file.
3. Run Il2CppDumper on the dump **with the base address** when auto-detection fails. On one sample
   the base `0x7ad74c3000` produced `CodeRegistration 0x7ad85254d0` and
   `MetadataRegistration 0x7ad856ff38`; those offsets are sample-specific.
4. If the metadata was decrypted in place at load, dump metadata from the same process as well:
   comparing the APK file with the memory image is how the in-place transform is proved.

The dump loses section headers and dynamic symbols. A disassembler will open it and show no
symbols; that is an ELF-metadata problem, not a bad dump.

### 4.1 Repairing the dumped ELF

Set, for every program header:

```text
p_offset = p_vaddr
p_filesz = p_memsz
```

The end of the last `PT_LOAD` is the original section-header offset. In one sample the eleventh
program header ended at `0x13BC000 + 63352 = 0x13CB778`, and that value belonged in `e_shoff`;
that arithmetic is the reusable part, not the address.

Then:

- `e_shstrndx` names a section whose `sh_addr` is 0 because it is not file-resident. Find the
  neighbouring section with the same `sh_offset` and a valid `sh_addr`; copy that address over the
  broken field.
- Set every section's `sh_offset = sh_addr`.
- Copy the section-header bytes into the file if they were not dumped, then re-analyse.
- Rebase the database to the dump's load address **before** importing headers or scripts.

After repair, import the IL2CPP tables in the order `unity-runtime.md` §4 gives. Running the
struct script twice (once with `script.json` + `il2cpp.h`, once with `stringliteral.json`) is the
order that names both functions and literals.

## 5. When the version field lies

A header can say version 31 while its tail is a long run of zeros and it lacks the fields that
version introduced. In one build, three separate failures traced to one integer:

- The dumper auto-located `CodeRegistration` at a wrong address; setting it manually was required.
- Metadata claimed 31, but the struct was a 29 layout; patching the version constant to 29 made the
  dumper proceed.
- A `methodDef` parse failed because one field was read at `+0x20` where the build used `+0x24`.
  Lowering the version constant in the dumper source fixed the stride.
- A large `libil2cpp.so` can make `genericMethodPointersCount` look like a 29.1 layout even when the
  version was already forced to 29; force the constant in the dumper rather than accepting the
  heuristic's label. Size is not a version.

**The version integer is a claim; the struct layout is evidence.** Validate a candidate layout by
plausibility: string offsets inside the file, counts that fit the remaining bytes, section tables
that are monotone, and a first string that is a real identifier (`mscorlib` is a useful landmark).
Do not "upgrade" a dump because the version says so.

A related trap: after a successful dump, only one region may be wrong. If the string blob's first
entry is garbage while the rest of the header is coherent, the blob is decrypted in place at load
(§4); do not discard the whole metadata image.

## 6. String literals: index space, encoding, re-import

When only literals are encrypted, the header arithmetic is stable:

- entry size is `8` bytes: `<int32 length, int32 dataIndex>`;
- entry `i` is at `stringLiteralOffset + i*8`;
- the bytes are at `stringLiteralDataOffset + dataIndex`, `length` bytes;
- the count is `stringLiteralSize / 8`.

The recovered value is UTF-8 in the metadata, but the runtime `Il2CppString` is UTF-16LE. When
hooking `il2cpp::vm::String::NewLen`, convert UTF-16LE to UTF-8 **before** writing back, or the
re-imported metadata is silently corrupt and the dumper still accepts it.

Dump `index,hex` to CSV, decrypt offline, patch the metadata file, then re-run Il2CppDumper. This
keeps the proof in one place: the tool either parses the patched file or it does not.

**When the literal cipher lives inside the protected VM, do not reverse it — drive the runtime.**
`String::NewLen(ptr, len)` *is* the decryption oracle, and it takes exactly the two fields the literal
table stores. Enumerate `i` from 0 to `count-1` yourself, read `(dataOffset + dataIndex, length)`, call
the runtime entry for each, and collect the returned UTF-16 buffers. Three properties make this better
than either hooking natural calls or reimplementing the cipher: it is exhaustive rather than a sample
of what the app happened to load, it is a completeness proof for the table (every index either
decrypts or visibly fails), and it keeps you out of the VM. The cost is that the process must be
alive and past metadata init, so it is the wrong route when the question is what a dead sample
contains.

## 7. Adjacent artifacts that fail the same way

These are not metadata, but they are the next files the same build protects, and the diagnostic
shape is shared.

- **AssetBundle header patched by the engine.** One build reports a fabricated Unity version
  (suffix `p1`) and XORs the first 32-bit field of each block and each directory node's size with
  `0x1024`. The fix is in the reader (AssetStudio), not in the bundle: apply the same XOR before
  parsing.
- **Repeating-key XOR over bundles.** With one plaintext sibling, XOR the two headers to recover
  the 16-byte key. Only the first few tens of KB need decrypting for the tooling to accept the
  file; the body can stay encrypted until an asset is actually needed.
- **Byte-inversion AssetBundle wrapper.** A custom `Stream` skips 4 bytes and inverts the next 5,
  then a second wrapper inverts bytes 0..4 of every 8-byte block, applied only to the 128-byte
  header. Script it as a header transform; do not invert the whole file.
- **CRC32-named paths and blend shapes.** Names in animation data are CRC32 of the full path,
  displayed as bare integers. Recover the prefix from uncompiled sources or the middleware's SDK,
  then build the name→CRC map. A hash is not encryption, but without the prefix it is not a name.

## 8. Order of attack

1. Decide the shape (§1).
2. If the metadata is file-resident and cheaply wrapped, decrypt statically (§3) and validate the
   magic and the first string.
3. If the loader is per-version or the file is absent, dump the consumer's output and the second
   `.so` mapping (§2, §4).
4. Repair the ELF only if a disassembler must consume the dump (§4.1).
5. Validate the metadata version against the struct before trusting any field (§5).
6. Recover literals last, and re-import them into the tool that must parse the result (§6).

## 9. Boundary

Every procedure here stops at a dependency you must supply: a device that can run the game, a
dumper version that matches the metadata layout, or the loader's own container format. None was
exercised in this record. The steps that would make a row `observed`: decrypt one file and show
the magic and first string, dump one live image and show a named function in the disassembler, and
re-import one literal table and show the dumper accepting it. Until then, treat the offsets as
examples, not as constants, and do not present a repaired dump as a working target without running
the feature it belongs to.
