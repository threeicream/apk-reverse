# Loading, dumping and repairing a protected `.so` at the linker level

Load this when a custom loader or packer sits between the APK and a usable native image: an
unpacked `.so` will not `dlopen`, a dump validates as ELF but crashes on load, a repaired
`soinfo` points at garbage, or you need to know *where* in the load pipeline it is safe to take a
dump. `native-and-so.md` owns patching and which library is actually loaded;
`code-virtualization-and-custom-linkers.md` owns recognising the loader and the keep-it/drop-it
deadlock; `advanced-unpacking.md` owns the dump routes above this layer. This file is the linker
contract those files assume.

**Claim strength.** The load/link pipeline and field layouts are absorbed from two public
source-reading write-ups (Android 5.0 and 8.x `bionic/linker`) and one Frida cookbook; no loader
was reimplemented and no dump was produced here. Source citations are `unverified` against your
tree until you open the matching AOSP tag. The *arithmetic* (bias, page offset, relocation target)
is `inferred` from that source and should be checked with one control load before it is trusted.
The `soinfo` offsets quoted below are explicitly version-specific and are examples, not constants.

## 1. The pipeline, as a specification for a loader

A loader must reproduce what `bionic` does without assuming a filesystem-backed file. The chain,
with the units that matter:

```text
dlopen
  -> do_dlopen
     -> find_library
        -> find_library_internal
           -> find_loaded_library_by_soname      (already loaded? return its soinfo)
           -> load_library
              -> ElfReader::Read                ReadElfHeader / VerifyElfHeader
                                                ReadProgramHeaders / ReadSectionHeaders
                                                ReadDynamicSection
              -> ElfReader::Load                ReserveAddressSpace / LoadSegments / FindPhdr
              -> soinfo_alloc                   link into the global soinfo list
              -> soinfo_link_image              prelink + relocate
     -> CallConstructors                        dependencies first, then own init/init_array
```

A custom loader that mirrors these eight calls is functionally a linker. That is why "the shell
decrypts a `.so` and calls `dlopen` on the plaintext" is the easy case, and "the shell never
writes a valid file" is the case that needs the field-level repair below.

`VerifyElfHeader` rejects: wrong magic, class mismatch, endianness, `e_type`, version != 1,
machine mismatch. A packer that corrupts `e_ident` cannot rely on system loading at all, so it
must carry its own loader. That is a useful diagnostic: if the file's header is deliberately
invalid, look for a loader before trying to repair the file for `dlopen`.

`load_library` reads `DT_RUNPATH` and `DT_SONAME` from the dynamic array *before* `prelink_image`
overwrites them from `PT_LOAD` data. A reimplementation that skips this loses the `soname` used by
`find_loaded_library_by_soname`, and a second `dlopen` of the same library then loads a duplicate.

## 2. Address arithmetic that every repair depends on

### 2.1 Load size and bias

```text
min_vaddr  = min(p_vaddr for PT_LOAD)
max_vaddr  = max(p_vaddr + p_memsz for PT_LOAD)
load_size  = page_align_up(max_vaddr) - page_align_down(min_vaddr)
load_bias  = load_start - page_align_down(min_vaddr)
```

For an ordinary shared object `min_vaddr == 0`, so `load_bias == load_start`. For a protected
image with a non-zero first segment, the difference is exactly the bias. **Every** `vaddr` to
runtime conversion adds `load_bias`, never the mapping base, and a repair that writes `base` where
`bias` is required produces addresses off by the first segment's page.

### 2.2 Mapping one segment

```text
seg_start       = page_align_down(p_vaddr + load_bias)
seg_end         = page_align_up(p_vaddr + load_bias + p_memsz)
file_page_start = page_align_down(p_offset)
file_length     = page_align_up(p_offset + p_filesz) - file_page_start
mmap(seg_start, file_length, prot, flags, fd, file_page_start)
```

For a memory-sourced payload the sequence is: reserve anonymous memory, then `memcpy` into
`seg_start + seg_page_offset`, where `seg_page_offset = p_offset & (page_size - 1)`. Omitting
`seg_page_offset` is the classic silent corruption: the segment is page-aligned on the file side
but its first bytes belong at a non-zero offset inside the destination page.

## 3. Parse `DT_*` first; treat `soinfo` as volatile

The dynamic section is the stable ABI. `prelink_image` is a `switch(d_tag)` terminated by
`DT_NULL`:

| Tag | Meaning | Address form |
|---|---|---|
| `DT_HASH` | SysV hash table: `nbucket`, `nchain`, `bucket[]`, `chain[]` | `load_bias + d_ptr` |
| `DT_GNU_HASH` | GNU hash: `nbucket`, `symndx`, `maskwords`, `shift2`, bloom, buckets, chain | `load_bias + d_ptr` |
| `DT_STRTAB` / `DT_STRSZ` | string table and size | pointer uses bias, size is a value |
| `DT_SYMTAB` / `DT_SYMENT` | symbol table; `DT_SYMENT` must equal `sizeof(ElfW(Sym))` | pointer uses bias |

Both hash formats must be handled: a repaired `soinfo` that carries only the one the shell happens
to use will fail `dlsym` for symbols that exist. `DT_GNU_HASH` validates that `maskwords` is a
power of two and stores `maskwords - 1`. The symbol count is not stored in the GNU format; it is
derived from the highest chain index, which is why "the symbol table looks one entry short" is a
parse bug, not a stripped export.

## 4. Relocation rules and the two biases

| Type | Value written | Note |
|---|---|---|
| `R_*_RELATIVE` | `load_bias + addend` | no symbol |
| `R_*_GLOB_DAT` | `sym_addr + addend` | data import |
| `R_*_JUMP_SLOT` | `sym_addr + addend` | `bionic` processes it like a normal reloc; lazy binding is not a separate path |
| `R_*_IRELATIVE` | `ifunc_resolver(load_bias + addend)` | may need temporary exec permission when the page is read-only |

Two addresses are in play and mixing them is the most common silent bug:

- the **definition**: `sym_addr = symtab[sym].st_value + defining_soinfo->load_bias`;
- the **slot**: `write_addr = r_offset + caller_soinfo->load_bias`.

A symbol resolved from a dependency uses the *dependency's* bias. A relocation in the caller uses
the *caller's* bias. They are equal only when both libraries loaded at the same base.

### 4.1 Packed relocations

If the table pointed to by `DT_ANDROID_REL`/`DT_ANDROID_RELA` begins with `"APS2"`, the body is
SLEB128-packed and must be read with the packed-relocation iterator starting after the 4-byte magic. A loader that assumes
plain `ElfW(Rel)` arrays produces a GOT full of garbage that still "looks like" relocated data.
This is an easy accidental symptom after hand-writing a loader; check the tag's first four bytes
before interpreting the table.

## 5. Repairing `soinfo` after an in-memory load

A loader that maps and relocates the payload still has to hand the result to the runtime. The
minimal field set one write-up reports as sufficient:

```text
base, size, load_bias
sym_tab, str_tab
nbucket, nchain, bucket, chain
ARM_exidx, ARM_exidx_count
```

The acquisition method is `dlopen(self, RTLD_NOW)` for the loader's own `soinfo`, then overwrite
the fields with the protected image's values. Two cautions:

- **Offsets are version-specific.** One 64-bit example walked the global `solist` with `next` at
  `+40`, `name` at `+408`, `base` at `+16`, `size` at `+24`, `load_bias` at `+256`. Those
  numbers hold for one cited build. Resolve `solist` by symbol
  (`__dl__ZL6solist`) and take the layout from the matching AOSP tag, or use the `dlopen` handle
  instead of walking the list.
- **A repair is not a load.** Overwriting `soinfo` makes symbols resolvable through the linker;
  it does not run constructors, apply `DT_NEEDED` dependencies, or register the image with the
  runtime's own bookkeeping. If the feature calls into the library before constructors would have
  run, it fails in a way that looks like a bad relocation.

## 6. Where it is safe to take a dump

The dump is valid only in the window where segments are mapped but relocation is not complete, or
after relocation if you also record the bias. Four practical hook points:

1. **`mprotect`** — flag calls granting `PROT_EXEC` on a large range. The "allocate then make it
   executable" pattern is a stager. The same call is used offensively: skip the exec grant when a
   debugger is present, which is a reason a hook may see the allocation and not the execution.
2. **`mmap`** — large file-backed mappings are likely the payload; anonymous large mappings are
   likely the decrypted image. Record `(addr, len, prot)`.
3. **`ElfReader::LoadSegments` / the loader's segment-copy loop** — after the copy, before link
   fixups. This is the cleanest point because the image is complete and the loader's own state is
   still available.
4. **The `soinfo` list** — enumerate every loaded object and record `base`, `size`, `load_bias`.
   This gives the dump bounds without knowing the packer, and it is version-portable if you resolve
   the list head by symbol.

Record the bias with the dump. A dump without its bias is only usable if you can recover the first
segment's `p_vaddr` from the program headers and prove the alignment.

### 6.1 Anti-dump by header corruption

A shell may XOR selected `PT_LOAD` fields after loading (`p_vaddr`, `p_memsz`, `p_filesz`,
`p_offset` with one constant) and restore them at use time. The dump then fails ELF validation
even though the code is intact. Detect it with invariants rather than by guessing the constant:

- `p_vaddr` is page-aligned for a loadable segment;
- `p_filesz <= p_memsz`;
- `p_offset` is monotone across program headers and page-aligned in the usual way;
- the first `PT_LOAD` covers the ELF header for a normal executable.

Test a candidate constant by applying it to all four fields and re-checking those invariants. A
uniform XOR survives every check that looks at one field alone.

Deleting the header instead of XORing it is a weaker defence but a nastier symptom: the file is
*cleanly* rejected, so the analyst blames the dump site. If the dump site is right and the header
is missing, the correct conclusion is "the shell removed it", not "the dump was early".

## 7. Timing: constructors and one-shot registrations

`dlopen` does not return until `CallConstructors` has run the dependencies' constructors, then the
library's `init`, then its `init_array`. Two consequences:

- A breakpoint on `do_dlopen` or `CallConstructors` catches unpacking before user code runs.
- A hook installed after the library is already loaded misses every one-shot registration. A
  `RegisterNatives` table is walked once; spawn the process under instrumentation or gate on
  `dlopen`/`android_dlopen_ext`, and run the real hook in `onLeave` when the module is mapped.

The `dlopen` symbol name differs by Android version; hook both `dlopen` and
`android_dlopen_ext`. A module that is mapped but not yet resolvable returns no base address, and
that is a timing failure, not a missing module.

## 8. Boundary

This file describes the contract, not a working unpacker. Nothing here was compiled against a
device's `linker` or used to load a real protected library. The steps that would make a row
`observed`: load a trivial `.so` from memory with the arithmetic above, show one symbol resolved
through the repaired `soinfo`, and dump one protected image at `LoadSegments` and open it in a
disassembler with symbols. Until then, treat every offset as a lead and verify the bias with a
control library that loads normally.
