# Reading a VM protector: envelope, virtual eflags, and trace search

Load this when a native function turns out to be an interpreter but the usual "find the dispatcher"
advice does not fit: `cmp`, `sub` and conditional jumps are missing, the trace is dominated by
`and/or/not/shr/neg`, a flags value is written into a stack slot, or a `ret` lands back at a VM
entry instead of the next instruction. `native-vm-recovery.md` owns the Android-side dispatcher
slicing and register anchoring; `vmp-differential-analysis.md` owns the Dex-level opcode
differential; `native-dbi-and-deobfuscation.md` owns the trace mechanics. This file owns the
*protector idiom* that sits on top of all three.

**Claim strength.** Absorbed from three public write-ups on x86 VMProtect-style targets and one
practical crack (2024-2026). The envelopes, instruction sequences and trace counts are quoted from
those samples and are `unverified` here; the general rules (anchor on data, trace then search by
constant, patch the flag value rather than the branch) are `inferred` from the same sources. No
VM-protected binary was traced in this record. Addresses and probabilities below are one sample's,
not constants.

## 1. Envelope triage

A VM protector is recognisable before any handler is read:

| Signal | What to look for |
|---|---|
| A new section | `vmp`/`VMP0`-named, often hundreds of KB on a small binary; the section's raw size is a large fraction of the image |
| Entry stub | first instruction is a `jmp`, followed by `push <imm>; call <target>`; the prologue does not match the compiler's idiom (no `push ebp; mov ebp, esp`) |
| Saved physical state | a block of `push` instructions with no matching `pop` before the transfer |
| Dispatcher shape | `mov reg, [index*4 + table]`, or handler-to-handler `jmp reg` / `push reg; ret` |
| Data pointer | a register loaded from the stack and then adjusted by an addend; this is the VM bytecode pointer, not a normal local |

Procedure: open the section in the debugger, set a **memory access breakpoint** on it, run, and
catch the first `push imm; call`. Delete the section breakpoint once you are inside; it fires on
every handler and will drown the session. The same entry is reachable from a hardware breakpoint on
the section's first page when software breakpoints are detected.

## 2. VM anatomy, in the order the fields appear

The names are conventional; the layout is what matters.

- **VM_DATA**: the encrypted bytecode. A pointer is staged through the stack, then adjusted by an
  addend to the real base. Handler dispatch reads the next opcode from it.
- **VM_CONTEXT**: virtual registers. One sample carved `0xC0` bytes with `sub esp, 0xC0`; slots
  are addressed as `[esp + virtual_reg_offset]`, with values staged through a scratch register.
  `0xC0 / 4 = 48` virtual registers is a useful sanity check.
- **vEIP**: the virtual instruction pointer. In one family it is `ESI`; in another it is a field in
  VM_CONTEXT. It points into VM_DATA or at the next handler, depending on the threading style.
- **vStack**: `EBP` marks its top; slots are `[ebp + off]`. The VM checks stack fullness by
  comparing top against bottom, which is the one place a normal stack discipline survives.
- **Physical saves**: below the virtual context, so that leaving the VM can restore the host state.

Two dispatch styles appear in the same product line:

- **Central dispatcher**: a jump table indexed by opcode, with every handler returning to the
  dispatcher. Easy to find, easy to instrument.
- **Direct threading** (later versions): each handler ends with `jmp next` or
  `push next; ret`, so there is no single dispatcher. The stable signal is not a table but the
  repeated epilogue that loads vEIP and transfers.

Do not key a detector on a fixed register. One write-up saw `r9` in one sample and `rdx` in
another for the same role; the invariant is "one register carries the next handler and the landing
instruction is benign", not the register's name.

## 3. Anchor on data, not on code

Virtualisation destroys the call graph you would normally walk. The method that survives is
data-anchored:

1. Run the target with a distinctive input: a long repeated string, a unique serial, a value you
   can recognise in any buffer.
2. Let the expected failure path execute (a wrong-license dialog, an error string).
3. Find the failure string or your input in memory and set an **access breakpoint** on it.
4. At the break, unwind the stack's return addresses. Keep frames that belong to the target; drop
   loader, CRT and system frames.
5. Set breakpoints on those frames, re-run with a second distinctive input, and step until one frame
   shows your bytes. That frame is the comparison or the caller that owns it.
6. Replace the code-section breakpoint with a **read breakpoint on your input address** as soon as
   you have it. The VM section breakpoint fires constantly; the data breakpoint fires once per use.

The same technique finds the string decryptor: break on the buffer, then walk to the code that
writes it.

### 3.1 A forged return is a landmark, not a bug

If stepping out of a callee lands at a VM entry instead of the instruction after the call, the
return address was forged deliberately. That site is protected logic. Do **not** NOP the region:
one write-up crashed immediately because the VM state expected the forged transfer. The correct
next move is to keep the transfer intact and change the value the protected branch consumes (§5),
or to trace forward from the real entry.

## 4. Trace, then search by constant

A full trace is cheap to produce and impossible to read. The useful unit is a *constant* that the
emulated semantics must materialise. In one crack:

- the trace was 259,607 instructions and took hours;
- searching for `0x40` (the ZF bit) produced about 100 hits;
- filtering to `and` instructions and correlating operand values left three sites, whose
  execution counts were 1, 1 and 30;
- the discriminating context was `eax = 0x40`, `ecx = eflags`, and a preceding
  `not eax; not ecx` pair;
- forcing `eax = 0x40` at those three sites removed the registration check.

The reusable recipe:

1. Trace with a tool that stores disassembly, not only addresses and registers. A trace you cannot
   search is a log, not evidence.
2. Search for the semantic constant (`0x40` for ZF, `0x815` for the arithmetic flag mask,
   `0x80000000` for sign, a known comparison value).
3. Filter by instruction shape: the constant is usually an operand of `and`, not of `cmp`.
4. Correlate operand roles, not just values. `and eax, ecx` with `eax = 0x40` is a flag test;
   `and eax, ecx` with `eax = 0xFFFF...` is a mask.
5. Check execution counts. The handler that runs once per operation is not the one that runs once
   per check.
6. Patch the *value written back* to the virtual flags slot, not the instruction that computes it,
   when the same handler serves many operations.

### 4.1 Trace one call, not the process

A whole-process trace of a VM is unreadable and slow. Anchor it to a call site:

- resolve the call target from the instruction, including `rel32` manually when the tracer needs an
  absolute address (`e8`/`e9`, `rel = read_s32(addr+1)`, `target = addr+5+rel`); follow short
  `jmp` thunks (a handful of hops) rather than stopping at the first one;
- start at the callee entry and stop at the call's return address, so the trace contains exactly the
  operation you care about;
- keep per-thread state and log `module:VA!RVA insn | reg=before->after`; a trace without register
  deltas cannot answer "what did this handler compute";
- **suppress hot loops.** Count back-edges (a jump whose target is lower than the current address);
  after a small number of iterations `unfollow` the thread and garbage-collect, then install a
  one-shot interceptor at the loop's fall-through to resume. Without this, a VM's dispatch loop
  produces thousands of identical segments and buries the one iteration that differs.

This recipe is `unverified` here (one public write-up); the hot-loop suppression is the part that
decides whether the trace is usable at all.

## 5. Virtual eflags is data; patch the data

On a real CPU only a few instructions write flags directly. In a VM, eflags is a stack slot, so the
protector can synthesise any value it wants. A recurring synthesis is:

```text
eflags = (eflags1 & 0x815) + (eflags2 & ~0x815)
```

The two halves carry the arithmetic flags and the control flags; the sum combines them. The ZF
test is then `zf = eflags & 0x40`. A debugger breakpoint on the test sees the branch only after the
value is already wrong, which is why patching the branch is fragile: the same handler computes many
conditions. Patch the value stored into the virtual flags slot (force `0x40`) and every consumer of
that slot agrees.

This is also why a search for `cmp`/`sub` fails. Subtraction is lowered as
`a - b = ~(~a + b)`, and comparison is a flag synthesis, so the instruction mix contains no
`sub` at all. Recognise the identity before concluding the function is not a comparison.

## 6. The lowering idioms that make a VM look like crypto

### 6.1 The universal gate, and the naming trap

The sequence that dominates these traces is `not a; not b; and`, i.e. `~a & ~b`. That is **NOR**,
not NAND (`~(a & b)`), even though the write-ups call it NAND. Use the identities as emitted:

```text
f(a,b)    = ~a & ~b            ; the actual primitive (NOR)
Not(a)    = f(a,a)
Or(a,b)   = f(f(a,b), f(a,b))
And(a,b)  = f(f(a,a), f(b,b))
Xor(a,b)  = f(f(a, f(a,b)), f(b, f(a,b)))
```

Defining `f` as NAND and keeping the same right-hand sides swaps AND and OR — a mistake that
produces a plausible but wrong truth table. A protector that lowers everything through this gate
produces long runs of `not; not; and`, which reads as noise. Arithmetic is built the same way:

```text
add(a,b)   = loop: sum = a ^ b; carry = (a & b) << 1; until carry == 0
neg(a)     = add(~a, 1)
sub(a,b)   = add(a, neg(b))
mul(a,b)   = shift-add on b & 1
div(a,b)   = restoring division over 32 bits
```

The value of knowing this is diagnostic: a trace with no `sub` but thousands of `not/and` is not
"encrypted", it is lowered. Stop looking for the missing instruction.

### 6.2 Branchless select

A conditional move/select is lowered to:

```text
sub a,b; pushfd; pop x; and x,0x40; shr x,6      ; ZF -> bit 0
mov y,1; sub y,x                                 ; complement
neg x; neg y                                     ; 0 -> 0, 1 -> 0xFFFFFFFF
and x,f1; and y,f2; or x,y; call x               ; select one function pointer
```

Exactly one mask is all ones, so the AND/OR pair selects a target without a jump.

The same construction appears as a branchless `max`/`min`:

```text
flip(n) = n ^ 1
sign(n) = flip((n >> 31) & 1)
c = a - b; sa = sign(a); sb = sign(b); sc = sign(c)
dif = sa ^ sb; same = flip(dif)
returnA = dif*sa + same*sc
returnB = flip(returnA)
result = a*returnA + b*returnB
```

There is no branch to patch. Change the operands or the value the final select consumes, and verify
with both orderings of the input — a max built this way is easy to mistake for a checksum. The tell is a
register that holds `0x40` and a `shr` by 6; the control flow graph shows neither a `je` nor a
`jne`. If you patch the `sub` that feeds the flag, you change the selected function; if you patch
the final `call`, you change only one branch of the select.

### 6.3 Why this matters for an APK

The same idioms appear in native Android protectors, especially where a bytecode VM emulates
comparisons for a license or signature check. The envelope differs (ELF section, JNI entry), but
the trace signature is identical: no `cmp`, a flags slot, and NAND-shaped arithmetic. Use
`native-vm-recovery.md` for the handler-slicing procedure once you have decided it is a VM; use
this file to decide what the handler is *computing*.

## 7. Static checks around the dynamic route

- **Rebase before trusting offsets.** Compute the section-relative offset
  (`runtime_addr - image_base`) and apply it in both debugger and disassembler. One sample needed
  `0x3E6000 - 0x381000 = 0x65000` and a rebase to `0x380000` to land on the function.
- **Xrefs can be empty and still be correct.** In the same sample, 24 "callers" from IDA never hit
  at run time because the site was reached by `jmp` or `call reg`. An empty xref list is not
  evidence that the function is unused; it is evidence that the call is indirect.
- **Address stability is not guaranteed.** Some debuggers reopen a sample at a different base each
  run. Trust execution order and relative structure; re-derive absolute addresses per session.

## 8. Boundary

This is a reading method, not a devirtualiser. It tells you which value the protected branch
consumes and how to change it at run time; it does not reconstruct the original instruction stream.
Nothing here was run against an Android target in this record. The steps that would make a row
`observed`: trace one protected comparison, find the flags slot, force the value, and show the
failure path disappear with the VM still intact. Until then, treat instruction counts and offsets
as illustrative and keep a control run of the unmodified target.
