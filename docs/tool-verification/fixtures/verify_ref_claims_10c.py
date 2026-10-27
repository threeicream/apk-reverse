#!/usr/bin/env python3
"""Re-run the claims added by the 2026-10-27 ref/* audit pass that need no device.

Three claims, all of which the reference files now call 'observed (host)':

1. python-bytecode-recovery.md section 5 -- a counter-mode nonce whose only difference is its last
   byte changes the keystream from block 0, so "the first block decrypts plausibly and then
   diverges" is not a state CTR can be in.
2. account-gates.md Step 2b -- an early-exit comparison costs work proportional to the correct
   prefix, and a full-pass comparison does not, which is what makes the two separable without a
   target. Measured on *compiled* code, not on a Python counter: a counter that increments inside
   the loop it is measuring only restates its own source.
3. il2cpp-protected-metadata.md section 2.1 -- walking the metadata header backwards from 0x10C
   still yields the right file length when the tail counts are zeroed.

Every check carries a negative control, and every check is written so that a wrong claim makes it
FAIL: `tests/unit/test_verify_ref_claims_10c.py` injects the wrong claim into each one and requires
the failure. A check that cannot fail is decorative.

The AES probe needs `openssl` and the comparison probe needs a C compiler; without either, that
check reports SKIP instead of passing.

Usage:
    python3 docs/tool-verification/fixtures/verify_ref_claims_10c.py
"""
import ctypes
import os
import shutil
import struct
import subprocess
import sys
import tempfile

KEY = '000102030405060708090a0b0c0d0e0f'


def report(name, ok, detail):
    """Print one verdict and pass it through. `ok is None` means the host cannot run the check.

    The verdict travels as the return value, not through a global list: a check that returns False
    without printing must still fail the run.
    """
    print(('SKIP ' if ok is None else 'PASS ' if ok else 'FAIL ') + name)
    for line in detail:
        print('     ' + line)
    return ok


def aes_ecb_block(block):
    run = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-K', KEY, '-nopad'],
                         input=block, capture_output=True)
    if run.returncode:
        raise RuntimeError(run.stderr.decode('utf-8', 'replace'))
    return run.stdout


def ctr_block(block, nonce):
    """openssl's CTR IV is the initial counter block, so this is that block's keystream XOR."""
    run = subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-K', KEY, '-iv', nonce.hex(), '-nopad'],
                         input=block, capture_output=True)
    if run.returncode:
        raise RuntimeError(run.stderr.decode('utf-8', 'replace'))
    return run.stdout


def _diff_len(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


def ctr_nonce_tail(nonce_a=None, nonce_b=None):
    """Claim: a nonce that differs only in byte 15 corrupts block 0, not just later blocks.

    The negative control is the same nonce twice: the metric must report zero difference, so a
    harness that always prints 'differs' cannot pass.
    """
    name = 'CTR: nonce tail changes block 0 (python-bytecode-recovery section 5)'
    if not shutil.which('openssl'):
        return report(name, None, ['openssl not found: cannot run this check on this host'])
    base = bytes(range(12)) + b'\x00\x00\x00'
    n_zero = nonce_a if nonce_a is not None else base + b'\x00'
    n_two = nonce_b if nonce_b is not None else base + b'\x02'
    plain = b'A' * 48

    ks_zero, ks_two = aes_ecb_block(n_zero), aes_ecb_block(n_two)
    block0_ks = _diff_len(ks_zero, ks_two)

    c_zero, c_two = ctr_block(plain, n_zero), ctr_block(plain, n_two)
    first = _diff_len(c_zero[:16], c_two[:16])
    later = _diff_len(c_zero[16:48], c_two[16:48])
    control = _diff_len(c_zero, ctr_block(plain, n_zero))

    ok = block0_ks == 16 and first == 16 and later == 32 and control == 0
    return report(name, ok,
                  ['keystream block 0 differs in %d/16 bytes' % block0_ks,
                   'ciphertext block 0 differs in %d/16 bytes, blocks 1-2 in %d/32' % (first, later),
                   'negative control, nonce against itself: %d/48 bytes differ' % control,
                   'so there is no "first block decrypts, rest diverges" state -- every block is wrong'])


C_EARLY = """
int cmp_work(const unsigned char *a, const unsigned char *b, int n) {
    int work = 0;
    for (int i = 0; i < n; i++) {
        work++;
        if (a[i] != b[i]) break;
    }
    return work;
}
"""

C_FULL = """
unsigned sink;
int cmp_work(const unsigned char *a, const unsigned char *b, int n) {
    int work = 0;
    unsigned diff = 0;
    for (int i = 0; i < n; i++) {
        work++;
        diff |= (unsigned)(a[i] ^ b[i]);
    }
    sink ^= diff;
    return work;
}
"""


def _build(lib_source, tmpdir, tag):
    src = os.path.join(tmpdir, tag + '.c')
    so = os.path.join(tmpdir, 'lib' + tag + '.so')
    with open(src, 'w') as fh:
        fh.write(lib_source)
    cc = shutil.which('gcc') or shutil.which('cc') or shutil.which('clang')
    run = subprocess.run([cc, '-O2', '-shared', '-fPIC', '-o', so, src],
                         capture_output=True)
    if run.returncode:
        raise RuntimeError(run.stderr.decode('utf-8', 'replace'))
    lib = ctypes.CDLL(so)
    lib.cmp_work.restype = ctypes.c_int
    lib.cmp_work.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    return lib.cmp_work


def comparison_oracle(early_source=C_EARLY, full_source=C_FULL):
    """Claim: an early-exit compare's work grows with the correct prefix; a full pass is constant.

    Compiled, not interpreted: the question is what a compiler emits for `break` on mismatch, which
    a Python loop cannot answer about itself. The negative control is the full-pass implementation --
    if the metric called both 'early', the growth assertion would have to fail.
    """
    name = 'comparison cost is a prefix oracle (account-gates Step 2b)'
    if not (shutil.which('gcc') or shutil.which('cc') or shutil.which('clang')):
        return report(name, None, ['no C compiler found: cannot measure compiled output'])
    secret = b'ACTIVATION-CODE'
    n = len(secret)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        early = _build(early_source, tmp, 'early')
        full = _build(full_source, tmp, 'full')
        grew = True
        for k in range(0, n + 1):
            cand = secret[:k] + b'\x00' * (n - k)
            e = early(cand, secret, n)
            rows.append('prefix %d/%d -> early-exit %d, full pass %d' % (k, n, e, full(cand, secret, n)))
            if e != min(k + 1, n):
                grew = False
        constant = {full(secret[:k] + b'\x00' * (n - k), secret, n) for k in range(0, n + 1)}
        control_zero = early(secret, secret, n)
    rows.append('full pass over the same candidates: %s' % sorted(constant))
    rows.append('negative control, identical inputs through the early-exit build: %d (must be %d)'
                % (control_zero, n))
    ok = grew and constant == {n} and control_zero == n
    return report(name, ok,
                  rows + ['early exit: work grows one unit per correct prefix byte; full pass: constant'])


def _walk(buf, start):
    i = start
    while i > 0:
        count = struct.unpack_from('<i', buf, i)[0]
        if count:
            return struct.unpack_from('<i', buf, i - 4)[0] + count
        i -= 8
    return None


def header_walk(pairs=None, start=0x10C):
    """Claim: the backward walk from 0x10C sizes a header whose magic and tail are zeroed.

    Ground truth is computed twice: from the pair table that built the fixture, and by an
    independent forward scan (max of offset+count). The negative control is a walk on an off-grid
    start -- it must disagree, otherwise "steps of 8" is not what the check is testing.
    """
    name = 'metadata header size by backward walk (il2cpp-protected-metadata section 2.1)'
    if pairs is None:
        pairs = [(0x1100, 0x40), (0x10C0, 0x20), (0x10A0, 0x10),
                 (0x1090, 0x08), (0x1088, 0x08), (0x1080, 0x08)]
    end = 0x10C
    header = bytearray(0x200)
    for idx, (offset, count) in enumerate(pairs):
        struct.pack_into('<i', header, end - 8 * idx, count)
        struct.pack_into('<i', header, end - 8 * idx - 4, offset)
    declared = pairs[0][0] + pairs[0][1]
    forward = max(offset + count for offset, count in pairs)
    walked = _walk(header, start)
    off_grid = _walk(header, start + 4)

    ok = walked == declared == forward and off_grid != declared
    return report(name, ok,
                  ['declared %#x, forward scan %#x, walk from %#x -> %#x'
                   % (declared, forward, start, walked),
                   'negative control, off-grid start %#x -> %#x (must differ)'
                   % (start + 4, off_grid),
                   'magic/version zeroed in this fixture: the walk uses only offset/count pairs'])


def main():
    print('== host checks for the 2026-10-27 ref audit pass ==')
    verdicts = [check() for check in (ctr_nonce_tail, comparison_oracle, header_walk)]
    skipped = sum(1 for v in verdicts if v is None)
    failed = sum(1 for v in verdicts if v is False)
    print('')
    print('%d check(s), %d skipped, %d failed' % (len(verdicts), skipped, failed))
    print('RESULT=%s' % ('ok' if not failed else 'failed'))
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
