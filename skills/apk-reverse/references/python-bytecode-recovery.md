# Python bytecode behind a packer: Pyarmor and the `.pyc` route

Load this when the logic you need is not Java, Kotlin, Dart or native, but Python: the APK embeds a
Python runtime (Chaquopy, Kivy, BeeWare), ships a `.pyc`/`.pyz`, or the companion desktop tool
that produces the data you are analysing is a PyInstaller/Pyarmor build. This file covers static
recovery of Pyarmor-protected bytecode; `emulation-and-rpc.md` owns calling the recovered routine
instead of reading it, and `framework-runtimes.md` owns deciding whether the runtime is Python at
all.

**Claim strength.** Absorbed from one detailed public write-up on a Pyarmor build and a modified
`pycdc` (2026). The field layouts, flags and opcode numbers are `unverified` here; no Pyarmor
sample was unpacked in this record. The general rules (static-first, self-describing TLV,
mirror-the-host-codegen) are `inferred` from that source. Version numbers matter: every branch
below is gated on the `pycdc`/Python version, and applying a newer layout to an older file fails
silently rather than loudly.

## 1. Recognition

| Signal | Meaning |
|---|---|
| `pyarmor-vax-\d{6}` string | Pyarmor build tag; `000000` is the free build, other values are a customer id |
| A `.pyc` whose code object starts with a private opcode or a high-entropy body | encrypted code object |
| `pyarmor` runtime module, `__pyarmor__` import, or a bootstrap that loads a shared object | protected distribution |
| `m_flags & 0x20000000` on a code object | Pyarmor's `CO_PYARMOR_OBFUSCATED` marker |
| A string blob where the first byte has a small tag and the rest is random | per-string encryption |

The packer is not a general-purpose VM. It is a key schedule plus AES-CTR plus a small bytecode
VM that derives one XOR key. That makes the static route the cheap one: you do not need to run the
program to recover its code.

## 2. Key schedule

One observed build derives the master key with MD5 over four concatenated inputs:

1. the ASCII build tag `pyarmor-vax-{6 digits}`;
2. `RSA_KEY1`: the blob at file offset 0, length `0x10E`;
3. `RSA_KEY2`: the blob at `0x110 + 0x20 = 0x130`, length taken from the 4-byte field at
   header offset `+4`;
4. a 16-byte value XORed with `0xF1` first.

`RSA_KEY2`'s first 12 bytes are the `AST_nonce` used later. The resulting 16-byte digest is the
AES-128 key; the nonce plus the code metadata select the CTR offset. The exact blob offsets belong
to the observed version; read them from the bootstrap, do not assume them for another build.

### 2.1 The 12-byte nonce-XOR key

When a header field `xor_key_procedure_length` is non-zero, the packer runs a tiny VM over a
12-byte output. The VM is worth knowing because its bugs become your key:

```text
registers[8], only indices 0..5 and 7 are valid (one build remapped 15 -> 7)
cursor starts at in + 16
opcode 1: terminate
opcode 2,3,4,6,7: += -= *= ^= =   (destination is cur[1] >> 4)
opcode 5: /=, then overwrites registers[0] with the quotient — the x86_64 lowering
          keeps rax as both the dividend and the result
opcode 8: load, cursor += 2
opcode 9: store registers[cur[1] & 7] as 4 bytes at out+0
opcode 0xA: address setup/store, cursor += 6
opcode 0xB: store 4 bytes at out + cur[2], cursor += 3
unknown opcode: zero the 12-byte output and abort
```

The `idiv` side effect is the general lesson: when reimplementing a packer's VM, mirror the *host
code generation*, including register clobbers the author did not intend. A clean abstract
interpreter will produce a different key and every downstream field will decrypt to noise.

## 3. Parsing the code object

The protected file is a normal `.pyc` with extra fields, so the parser must be version-aware.
Fields that change and the versions that introduced them:

| Field | Width / condition |
|---|---|
| `m_argCount` | 16-bit for 1.3-2.2, 32-bit from 2.3 |
| `m_posOnlyArgCount` | present from 3.8 |
| `m_numLocals` | present below 3.11 |
| `m_localKinds` | present from 3.11 |
| `m_qualName` | present from 3.11 |
| `m_exceptTable` | present from 3.11 |

For files older than 3.8, the flags field is remapped before use:

```text
m_flags = (m_flags & 0x1FFF)
        | ((m_flags & 0xFFFE000) << 4)
        | (m_flags & 0x20000000)
```

Warn if `m_flags & 0xD0000000` is set: those bits are not part of the layout this parser knows.
Getting the remap wrong moves every subsequent field by four bytes and the failure looks like a
corrupt string table, not a version error.

## 4. The extra section: a self-describing TLV

After the code object's usual fields:

```text
1 byte   extra_length
256 bytes extra_data
```

Decode it as a small TLV, not as fixed offsets:

```text
if extra_data[0] & 0xF0: reject (unknown feature bits)
fn_count         = extra_data[0] & 3
descriptor_count = (extra_data[0] >> 2) & 3
ptr = extra_data + 4
for each item:
    item_len = (*ptr >> 6) + 2     ; low 6 bits are flags
    ...
```

Skip `fn_count` items, then walk `descriptor_count` items. For a descriptor item, ignore the low
6 bits of each byte and big-endian accumulate the remaining bits into a `consts_index`. That index
selects a string in the code object's constants; the string is the `descriptor`, and a descriptor
shorter than 20 bytes is invalid. The layout is self-describing precisely so the packer can change
the counts without changing the parser; hard-coding `fn_count = 1` breaks on the next build.

## 5. Decrypting one code object

The descriptor's first 8 bytes are not data: at run time they hold `&PyCodeObject`, and the
unpacker replaces them with the literal string `"<COAddr>"`. The rest is a struct at
`descriptor.data() + 8`:

```text
flags            = *(u32*)struct
copy_prologue    = flags & 0x8
xor_aes_nonce    = flags & 0x4
short_code       = flags & 0x2
decrypt_begin    = ...
decrypt_length   = ...
short_nonce_index= ...
```

Then:

1. Choose the nonce source index:
   `short_code ? short_nonce_index : short_nonce_index + decrypt_begin + decrypt_length`.
2. Copy 12 bytes from `m_code + nonce_index` into a zeroed 16-byte nonce, then set
   `nonce[15] = 2`.
3. If `xor_aes_nonce`, XOR those 12 bytes with the 12-byte VM key from §2.1.
4. AES-128-CTR decrypt `code[decrypt_begin .. decrypt_begin + decrypt_length]`.
5. If `copy_prologue`, copy `decrypt_begin_index` bytes from `code + decrypt_length` to `code + 0`,
   then fill `code[decrypt_length .. decrypt_length + decrypt_begin_index]` with `0x09` (NOP).
6. Replace the descriptor's first 8 bytes with the `"<COAddr>"` placeholder so a later re-run does
   not treat runtime data as a key.

The nonce construction is the part that is easy to get wrong: `nonce[15] = 2` is a domain
separator, and using an all-zero tail produces a stream that decrypts the first block plausibly and
then diverges.

## 6. Decrypting strings

Strings are separate from code and use a tag byte:

```text
v[0] & 0x80 == 0     -> not encrypted (skip)
v[0] & 0x7F == 0     -> empty/plain (skip)
(v[0] & 0x7F) > 4    -> not an encrypted string (skip)
otherwise:
    drop byte 0
    nonce = 12 bytes of pyarmor_mix_str_aes_nonce, nonce[15] = 2
    AES-CTR with the same master key
```

The tag is a type code, not a length. Treating the low 7 bits as a length is the usual way a
reimplementation decrypts some strings and corrupts the rest.

## 7. What to do with the result

- A recovered `.pyc` can be decompiled by a version-matched decompiler, but the bodies are only
  useful if the decompiler understands the Python version's opcodes. Pin both.
- If the decompiler fails on one code object, keep the decrypted bytes and read the disassembly
  (`dis`) rather than re-attacking the packer. The packer is solved once; the decompiler is a
  separate problem.
- If the goal is *calling* the routine rather than reading it, load the recovered module in the
  matching Python and call the entry point, or use the emulation/RPC route. Do not rebuild the
  cipher from a partial read when the decrypted function is in front of you.

## 8. Failure modes

| Symptom | Likely cause |
|---|---|
| Descriptor shorter than 20 bytes | wrong `consts_index` (bit accumulation ignored the low-6-bit skip) |
| Header fields shift by 4 after `m_flags` | wrong version remap (pre-3.8) |
| First block decrypts, rest is noise | nonce tail not zeroed + `nonce[15]` not set, or CTR offset wrong |
| VM key differs from the packer's | host-codegen clobber (`idiv`) not modelled |
| Some strings decrypt, others do not | tag byte treated as length, or the `> 4` guard missing |
| Code object decrypts but prologue is garbage | `copy_prologue` flag ignored, or NOP fill used the wrong length |

## 9. Boundary

This route is static and offline, which is its advantage: no device, no runtime, no root. It also
means every claim about a field is a claim about one Pyarmor version. Nothing here was run against
a real sample in this record. The steps that would make a row `observed`: parse one `.pyc`, show
the extra section counts matching the file, decrypt one code object, and execute the recovered
module to the same output as the original. Until then, treat the offsets as a template and keep the
original bytes so a wrong branch can be retried without re-extracting the sample.

For a packaged Android app, the Python payload may sit in `assets/` or be extracted on first run.
Locate it the same way as any other runtime: find the loader (the Python runtime's initialization
call), then the payload path it builds. `recon.md` owns that search; this file begins once a
protected `.pyc` is in hand.
