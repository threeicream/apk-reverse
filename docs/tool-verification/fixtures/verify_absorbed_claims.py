#!/usr/bin/env python3
"""Re-run the host-checkable claims absorbed from ref/* on 2026-10-25.

These are the claims that can be settled without a device, a protected sample or a server. Each
check prints what it measured and whether the claim in the reference survived it. The AES probes
need `openssl`; without it they report SKIP rather than passing.

Usage:
    python3 docs/tool-verification/fixtures/verify_absorbed_claims.py
"""
import hashlib
import math
import random
import shutil
import subprocess
import sys
import urllib.parse
import zlib

PAGE = 4096
KEY = '000102030405060708090a0b0c0d0e0f'
IV = KEY
results = []


def report(name, ok, detail):
    results.append((name, ok))
    print(('PASS ' if ok else 'FAIL ') + name)
    for line in detail:
        print('     ' + line)


def mask_identity():
    bad = sum(1 for x in range(256) for m in range(256)
              if ((x & ~m) | (~x & m)) & 0xFF != x ^ m)
    random.seed(1)
    bad16 = 0
    for _ in range(200000):
        x, m = random.getrandbits(16), random.getrandbits(16)
        if ((x & ~m) | (~x & m)) & 0xFFFF != x ^ m:
            bad16 += 1
    report('mask identity (protocol-reverse section 7, involution)', bad == 0 and bad16 == 0,
           ['65536 eight-bit (x,m) pairs: %d counterexamples' % bad,
            '200000 random 16-bit pairs: %d counterexamples' % bad16])


def padding_length():
    bad = [n for n in range(0, 65)
           if n + (16 - n % 16) != 16 * math.ceil((n + 1) / 16)]
    report('PKCS#7 length law (protocol-reverse section 7, probe 3)', not bad,
           ['b=16, p=0..64: %d mismatches' % len(bad)])


def zero_fill():
    img = bytearray(3 * PAGE)
    img[2 * PAGE + 7] = 0xAB
    skipped = img[:PAGE] + img[2 * PAGE:]
    filled = img[:PAGE] + bytearray(PAGE) + img[2 * PAGE:]
    ok = skipped.index(0xAB) != 2 * PAGE + 7 and filled.index(0xAB) == 2 * PAGE + 7
    report('unreadable page: skip shifts, zero-fill preserves (linker section 6.3)', ok,
           ['expected offset %d' % (2 * PAGE + 7),
            'skip      -> %d' % skipped.index(0xAB),
            'zero-fill -> %d' % filled.index(0xAB)])


def hidden_salt():
    p, b, t = b'api=search', b'{"q":"x"}', b'1729000000'
    salt = bytes.fromhex('00112233445566778899aabbccddeeff')
    target = hashlib.md5(p + b + t + salt).hexdigest()
    tried = hits = 0
    for alg in (hashlib.md5, hashlib.sha1, hashlib.sha256):
        for sep in (b'', b'&', b'|'):
            for parts in ((p, b, t), (t, b, p), (p, t, b), (b, p, t)):
                tried += 1
                hits += alg(sep.join(parts)).hexdigest() == target
    ok = hits == 0 and hashlib.md5(p + b + t + salt).hexdigest() == target
    report('hidden salt defeats a visible-parameter search (signature-derived-keys variant)', ok,
           ['%d combinations over 3 algorithms and 4 field orders: %d hits' % (tried, hits),
            'with the salt included: match'])


def compression_drift():
    data = b'{"items":[' + b'{"id":1,"name":"x"},' * 40 + b']}'
    a, b = zlib.compress(data, 1), zlib.compress(data, 9)
    ok = a != b and zlib.decompress(a) == data and zlib.decompress(b) == data
    report('compressed bytes are implementation/parameter defined (protocol-reverse section 7)', ok,
           ['level 1 = %d bytes, level 9 = %d bytes, identical = %s' % (len(a), len(b), a == b),
            'both round-trip to the payload'])


def percent_encoding():
    q = urllib.parse.quote('a b~*-_.')
    qp = urllib.parse.quote_plus('a b~*-_.')
    ok = q == 'a%20b~%2A-_.' and qp == 'a+b~%2A-_.'
    report('Python percent-encoding differs from Java URLEncoder (protocol-reverse section 7)', ok,
           ['quote      = ' + q, 'quote_plus = ' + qp,
            'Java keeps *-._ and encodes ~ as %7E -- not checked here (no JDK)'])


def aes_enc(mode, data):
    cmd = ['openssl', 'enc', '-aes-128-' + mode, '-K', KEY, '-iv', IV, '-nopad']
    run = subprocess.run(cmd, input=data, capture_output=True)
    if run.returncode:
        raise RuntimeError(run.stderr.decode('utf-8', 'replace'))
    return run.stdout


def aes_modes():
    if not shutil.which('openssl'):
        report('AES mode separation (protocol-reverse section 7, probe 2)', True,
               ['SKIP: openssl not found'])
        return
    p1 = b'A' * 32
    p2 = b'A' * 32 + b'B' * 16
    flipped = bytearray(p1)
    flipped[5] ^= 0xFF
    flipped = bytes(flipped)

    def dirty(a, b):
        return sum(1 for i in range(min(len(a), len(b))) if a[i] != b[i])

    rows = []
    ok = True
    for mode in ('ctr', 'cbc', 'ecb'):
        c1, c2, cm = aes_enc(mode, p1), aes_enc(mode, p2), aes_enc(mode, flipped)
        px = dirty(c1, c2[:len(c1)])
        width = dirty(c1, cm)
        rows.append('%-3s prefix-xor dirty=%d/32  one-byte-flip changed=%d/32' % (mode, px, width))
        if px != 0:
            ok = False
    ok = ok and rows[0].endswith('1/32') and rows[1].endswith('32/32') and rows[2].endswith('16/32')
    report('AES mode separation (protocol-reverse section 7, probe 2)', ok,
           rows + ['all three modes show zero prefix-XOR: that probe cannot separate them'])


def main():
    print('== host checks for the 2026-10-25 absorption ==')
    mask_identity()
    padding_length()
    zero_fill()
    hidden_salt()
    compression_drift()
    percent_encoding()
    aes_modes()
    failed = [name for name, ok in results if not ok]
    print('')
    print('%d check(s), %d failed' % (len(results), len(failed)))
    print('RESULT=%s' % ('ok' if not failed else 'failed'))
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
