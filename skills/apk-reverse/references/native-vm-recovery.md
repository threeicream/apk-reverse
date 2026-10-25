# Native VM recovery — from "this looks virtualized" to an IR you can read

Load this when a native function is an **interpreter** — a VM you cannot read statically, an
xvmp-class IR virtualizer, or any private-bytecode loop — and the question is how to get from
the handler soup to the guest program. This file owns the recovery procedure; the **capture**
half lives in `references/ete-diff-tracing.md`, the **slicing** tool in
`scripts/vm_handler_slice.py`, and the OLLVM-only case in
`references/native-dbi-and-deobfuscation.md`.

**Claim strength.** Every method step here is absorbed from two public reverse-engineering
write-ups (Kanxue, 2026-08/09, titles and authors anonymized in this record; one is a full
arm64 custom-VM recovery, the other a VMP interpreter recovery with trace-driven IR lifting).
The write-ups are `observed` by their authors; this repository has **never run any of these
steps on a real VM target**, so the mechanics below are `unverified` here — reported, not
reproduced — and the ordering judgements built on them are `inferred`, cross-read against the
open xvmp source facts in `references/ete-diff-tracing.md` §5. The pipeline's host-tested pieces
(trace parsing, slicing, diffing) carry their own labels where named.

## 1. Deciding it is a VM at all

None of the signals below proves a VM alone — a big switch, a state machine, a function-pointer
table and an event dispatcher all look similar. The judgement is **several appearing together**:

1. one large native function, called often, taking a chunk of external data;

If the missing piece is not the dispatcher but *what a handler computes* — no `cmp`/`sub`, a flags
slot written to the virtual context, `and/or/not` runs — `vm-protector-analysis.md` owns that idiom.
2. a loop that reads a cursor from one buffer, dispatches on the value read, and writes the
   cursor back — the `while(running){ opcode=code[pc]; execute(opcode); pc=next_pc; }` shape;
3. a **virtual register file**: many paths access `base + index*8` (or *4, *2) where *index*
   comes from small integers inside that data;
4. semantic blocks that end by advancing the cursor by **different fixed lengths** (pc+=4,
   pc+=5, pc+=7) all written back to the same context slot — a variable-length ISA;
5. (generator-produced xvmp shape) stubs that call `vm_exec(code, size, args, num)` with the
   bytecode and a boxed-argument array as module data — noting the public tree ships the
   compiler side only (a weak empty stub at runtime; `ete-diff-tracing.md` §5), so this
   signal means "a virtualizer of that family generated it", never "that repo's interpreter
   is present".

## 2. Two dispatchers stacked — the first wrong turn

When the interpreter itself was compiled with OLLVM flattening, you see **two state machines
nested**: CFF state → CFF dispatcher → native block → VM logic → VM state → VM dispatcher →
handler. Both have table+index+indirect-branch+state-update, and `LDR Xn,[table,index]; BR Xn`
proves nothing about which layer it is. Judge by behaviour, not shape:

| Question | CFF dispatcher | VM dispatcher |
|---|---|---|
| where does the index come from? | arithmetic on an internal state value (add/xor/csel chains) | a byte/word read from the **bytecode buffer** |
| do targets read bytecode / VM registers? | no — pure flattening blocks | yes — that is the fetch and the register file |
| do targets update the VM PC and return to fetch? | no — they compute the next CFF state | yes — `pc += n`, then back to fetch |

Mislabelling the CFF table as `VM_HANDLER_TABLE` poisons everything downstream: every
opcode→handler pair after it is wrong. The write-up's first correction was exactly this.

### 2.1 Encoded handler tables

A table entry does not have to be a pointer. One ARM64 sample stored 64-bit values that only become
targets after adding a constant (`table[i] + 0x740078FC`, yielding offsets such as `0x3BA04`).
Resolve both arms arithmetically before deciding which one is semantically required, then patch the
conditional, not the table. When a callee is patched, undefine and rebuild the caller, or the
decompiler keeps the stale target and the next reading is wrong.

### 2.2 A dispatcher invariant worth exploiting

When the obfuscator routes every transfer through one register (`r9` in one sample, `rdx` in
another) and the landing instruction is a benign `nop`, enumerate real blocks by filtering the trace
for "indirect jump through that register whose target begins with `nop`". That skips symbolic
simplification of the MBA expressions entirely. The register is sample-specific; the invariant is the
benign landing instruction.

## 3. Do not fully deflatten first — chase the VM data flow

Full native-CFG recovery of a flattened interpreter is expensive and unnecessary. What the VM
analysis actually needs is six things out of the flatten: **code_base, PC, opcode, descriptor,
register file, FLAGS, next_pc**. The method: walk CFF blocks, keep the ones that touch those
(the fetch pattern `insn = code_base + pc; opcode = insn[0]; desc = insn[1]` is unmistakable
once named), mark their inputs/outputs, and ignore pure flattening blocks.

## 4. A dispatch table of zeros is a relocation, not encryption

Dispatcher table entries that read as `0,0,0,...` are usually **`R_AARCH64_RELATIVE`
relocations** the loader fills at startup — not runtime decryption, and no dynamic trace is
needed: parse the ELF, enumerate relocations whose offset falls in the table, and
`targets[i] = image_base + reloc.addend`. That statically recovers the CFF state→block mapping
in bulk. (`scripts/trace_addr2sym.py` reads PT_LOADs; a relocation walker would be its natural
extension — currently **not shipped**.)

## 5. Proving which field is the VM PC

Three pieces of evidence, all required:

1. it **participates in the instruction-address computation** (`insn = code_base + value`);
2. handlers **update it deterministically** by the instruction length they implement;
3. the updated value is **written back to the same context slot** every dispatch — one
   `write IP` slot, however many addressing forms reach it (one write-up's VM had handlers
   writing `[x23]` and `[x19,#0xc]` — the *same slot* through two addresses; a seed that
   matched only one form missed a whole handler class).

## 6. Register anchoring, then triple verification

Anchor the interpreter's registers from one hand-read handler: which native register holds the
ctx base, the bytecode pointer, the IP, the handler table, each register-file base. Then verify
each anchor three ways before building anything on it:

1. **the initializer is the smoking gun** — the ctx-init function memsets the whole register
   file and pre-seeds known slots (one write-up: `memset(ctx+0x6070, 0, 0x381)`, and a
   register slot pre-set to `ctx+0x6030`, matching the trace exactly);
2. **trace statistics** — hundreds of thousands of `[base, idx, lsl #3]` accesses with idx
   strictly inside [0,31] sizes the file better than any guess;
3. **a uniform handler template** — all handlers take the same contract (`a1` = current VM
   instruction; operands at fixed offsets `[x8+8]/[x8+9]/[x8+0xA]`; register access always
   `*(x24 + 8*idx)`). One violating handler is a discovery, not noise (see §5).

## 7. Nested VMs: segments must be a stack

When VM entry can be **called from inside VM code**, a flat "current segment" accumulator
corrupts the trace reading: entering the inner VM discards the partially-collected outer
segment, and returning resumes into a false segment. In the write-up, 45 of 46 entries were
nested, each discarding 57–1997 instructions. The fix is a **segment stack**: push the
outer segment on entry, pop and continue on exit. `scripts/vm_handler_slice.py` slices a
single dispatcher level and now prints a diagnostic when a segment looks like a nested
dispatch loop (a block repeating inside one segment) — treat that as "this trace has more than
one level; slice per level", not as a final reading.

## 8. Recovering operands: slice backwards from the STOREs

Two lines per handler, and both start at the **stores**, not the head: forward from a handler
head diverges (one instruction writes several slots, each with its own history); backward from
the store **converges** (each location has one in-block definition — "last write before use",
no dataflow solver needed).

- **index line** = the STORE's address operand (which register slot);
- **value line** = the STORE's stored operand (what was computed);
- seed on **all** stores — writes to the register file *and* writes to memory. Seeding only
  register-file stores silently drops every pure-store handler class (one write-up lost 15 of
  266 handler entries this way; loads need no seed, the backward walk brings them in).

The decoder noise problem: one SLEIGH-style instruction expands into a wall of
shift/mask/or operators (the bytecode **decoder**, not VM semantics). The folding judgement
that worked is a **byte provenance** track — for each output byte, where did it come from:
bytecode space, ctx space, a pointer dereference, or a constant. A subtree folds into "one
read" only if: exactly one memory source; it lands on byte lane 0; and the value matches.
Value alone is not a criterion (two lanes can hold the same byte); provenance alone is not
(one source can be *shifted* into place, which is assembly, not extraction).

## 9. Proving semantics: run it, then distrust it

Static confidence is not enough for an interpreter — a 90%-right opcode poisons every later
step, and the failure mode is quiet: one write-up's first emulator wrote a 32-bit register as
`reg = (uint32_t)value;` when the real semantics were **write low 32 bits, keep high 32**;
only the high half differed, and later call arguments changed. The recovery loop:

1. implement a **clean re-VM** (your own interpreter for the recovered ISA) — do not instrument
   the original;
2. run **real captured bytecode** through it and compare against traced ground truth
   (registers/memory per step — the trace's read/write columns are the oracle);
3. one mismatch = one wrong semantic or one wrong instruction **boundary** (a descriptor
   misread shifts every later instruction), and both look identical until you re-derive the
   length table.

HOSTCALL is the second ABI you still owe: service ids, argument sourcing, return placement,
which parameters are pointers — until it is recovered, the IR stalls at `hostcall_xxx(a,b,c)`.

## 10. The IR shape that made patterns visible

One VM instruction per line, instance values inlined: `VREG[0x14] = sext(VREG[0xb] >> (VREG[0x14] & 0x1f))`,
`*(VREG[0x1]+0x498) = VREG[0x3] | 0x3` (the trailing `| ip` is the PC write-back). With that
rendering, **regularities surface by themselves** — consecutive stores with offsets stepping
by −8 and source slots descending turned out to be one struct-field bulk copy; and once the
pre-IP and post-IP are both recorded (`0x2 -> 0x3`), the 200k-line IR sequence *is* the guest
execution trace: +1 is fallthrough, jumps are branches, back-edges are loops — the guest CFG
falls out. That is the end state this file walks toward: the guest program as data.

## 11. The other end state: a program you can run

Sections 1–10 aim at a guest program you can **read**. When the interpreter implements one
deterministic function — a request signer, a decoder, a checksum — the cheaper deliverable is a
program you can **run**, and the handler semantics never need to be understood. (`unverified`: one
write-up reports the route; this record did not run it.)

1. **Fix the boundary.** One native entry that takes a buffer in and produces a buffer out.
   Everything inside is the VM; everything outside is protocol.
2. **Symbolic input, concrete everything else.** Seed the input bytes as symbols and run the VM (live,
   or over the recorded trace). Constant-fold every node whose value does not depend on them; delete
   loops and branches whose condition folds. What cannot fold is the part you must reproduce.
3. **What remains is straight-line.** An SSA list of `(op, args)`, where `args` are constants or the
   indices of earlier nodes, and `op` is the ALU subset the real semantics needed — read input byte,
   load from the constant table, add/sub, and/or/xor, shift, truncate, sign-extend. No loop, no
   dispatcher, no handler table.
4. **Capture four artifacts together, from one trace.** They are only valid as a set:
   - the program;
   - the constant table and its base (program offsets are relative to it);
   - the **output map** — which node byte lands at which output offset;
   - the **output template** — the fixed characters the transform does not compute.

   The map and the template are what people skip. Without them the transform is right and the string
   is wrong, which looks like an off-by-one in the algorithm and is not.
5. **Implement it in tens of lines.** A loop over `(op, args)` with a value array. No emulator, no JNI,
   no device — a function you can call at unit-test speed.

**Version binding.** The program is a property of one build. Store the library's fingerprint (size and
build id) beside it and re-extract on upgrade: the tables and the map move even when the algorithm
does not. Say which build a program came from; an extract with no fingerprint is not reproducible.
(`inferred` for the fingerprint discipline; `unverified` for the source's report that the tables move
on update.)

**Validation is per node, not per output.** Compare node values at several checkpoints against a
device run. A node that is right in value but wrong in width (32-bit truncation where the VM kept 64)
passes the final comparison on some inputs and fails on others — §9's failure seen from the other
side. (`inferred` from §9.)

**Boundary.** This route needs a deterministic, input-driven computation. If the VM folds in a device
id, a timestamp or a nonce, those become constants from one trace, and the honest claim is
"reproduces one device's answers", not "implements the algorithm". For a signer that is often exactly
enough, but the report has to say which claim it is making.

## 12. Where this repository's tools plug in

| Step | Tool |
|---|---|
| capture the interpreter loop (device with ETE) | `scripts/ete_capture.py` + `references/ete-diff-tracing.md` |
| slice/cluster the loop, opcode trajectory (known opcode table, xvmp) | `scripts/vm_handler_slice.py` |
| two-input divergence (which handler paths the input reaches) | `scripts/trace_diff.py` |
| watch the ctx / bytecode / boxed args without touching code | `scripts/hw_watch.py` + `references/hardware-watchpoints.md` |
| data flow without a known address (which code touches the key buffer) | SPE, `references/hardware-sampling-and-crash.md` |
| PC → symbol/static offset, handler tables | `scripts/trace_addr2sym.py` |
| static state→block mapping for the outer CFF (MOV/MOVK const propagation, CMP on the state register, predecessor walk past blocks with no CMP) | the OLLVM static route in `references/native-dbi-and-deobfuscation.md` §5, extended by the absorbed write-up's technique |
| relocation table recovery (§4) | not shipped — `elf_plt.py`/`trace_addr2sym.py` are the nearest readers |

## Checklist

- [ ] VM existence judged from §1's signals *together*, not from one look-alike switch
- [ ] dispatcher layer decided by §2's behavioural table before naming any table
- [ ] VM PC proven by all three §5 evidences; write-slot matched by address, not one register
- [ ] register anchors triple-verified (initializer / trace statistics / handler template)
- [ ] segments stacked if entry can nest (§7); slicer's nested-loop diagnostic honoured
- [ ] operand slicing seeded on all STOREs; byte provenance (not value) decides folding
- [ ] clean re-VM runs real bytecode against trace ground truth before any IR is trusted
- [ ] labels: write-up mechanisms `unverified`, ordering judgements `inferred`, shipped tools `observed` (host), no VM target run here
- [ ] if the deliverable is a callable signer/decoder: §11's four artifacts captured as a set, program pinned to a build fingerprint
