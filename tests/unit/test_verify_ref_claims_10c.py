"""The 2026-10-27 host fixture must be able to fail.

`docs/tool-verification/fixtures/verify_ref_claims_10c.py` is the only thing standing behind three
`observed` labels, so its checks are as load-bearing as a gate. The first draft failed the rule this
repository applies to gates: the comparison check counted iterations inside the Python loop it was
measuring, so `n == k + 1` restated its own source and could never fail for a real reason. It now
compiles the two comparators and measures the compiler's output.

Each test here injects the wrong claim and requires the check to reject it, plus one test that the
process exit code follows the verdict. `observed` on a host with neither `openssl` nor a C compiler
is a skip, not a pass.
"""
from __future__ import annotations

import importlib.util
import shutil

import pytest

from conftest import REPO_ROOT

pytestmark = pytest.mark.unit

FIXTURE = REPO_ROOT / "docs" / "tool-verification" / "fixtures" / "verify_ref_claims_10c.py"


@pytest.fixture(scope="module")
def claims():
    spec = importlib.util.spec_from_file_location("verify_ref_claims_10c", str(FIXTURE))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _need_openssl():
    if not shutil.which("openssl"):
        pytest.skip("no openssl on this host: the CTR check degrades to SKIP")


def _need_cc():
    if not (shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")):
        pytest.skip("no C compiler on this host: the comparison check degrades to SKIP")


def test_checks_pass_on_the_claim(claims):
    _need_openssl()
    _need_cc()
    assert claims.ctr_nonce_tail() is True
    assert claims.comparison_oracle() is True
    assert claims.header_walk() is True


def test_ctr_check_rejects_an_unchanged_nonce(claims):
    _need_openssl()
    base = bytes(range(12)) + b"\x00\x00\x00"
    same = base + b"\x02"
    assert claims.ctr_nonce_tail(nonce_a=same, nonce_b=same) is False


def test_comparison_check_rejects_a_full_pass_mislabelled_early(claims):
    _need_cc()
    assert claims.comparison_oracle(early_source=claims.C_FULL) is False


def test_comparison_check_rejects_an_early_exit_mislabelled_constant(claims):
    _need_cc()
    assert claims.comparison_oracle(full_source=claims.C_EARLY) is False


def test_header_check_rejects_an_off_grid_start(claims):
    assert claims.header_walk(start=0x110) is False


def test_header_check_rejects_ground_truth_that_disagrees(claims):
    # the tail-most pair no longer sits at the largest offset, so "declared" and the forward scan
    # cannot both be the file length
    pairs = [(0x1100, 0x08), (0x1300, 0x10), (0x10A0, 0x10)]
    assert claims.header_walk(pairs=pairs) is False


def test_main_exit_code_follows_the_verdict(claims, monkeypatch):
    # a check that returns False without printing must still fail the run
    monkeypatch.setattr(claims, "ctr_nonce_tail", lambda: False)
    monkeypatch.setattr(claims, "comparison_oracle", lambda: True)
    monkeypatch.setattr(claims, "header_walk", lambda: True)
    assert claims.main() == 1


def test_main_treats_a_skip_as_not_a_failure(claims, monkeypatch):
    monkeypatch.setattr(claims, "ctr_nonce_tail", lambda: None)
    monkeypatch.setattr(claims, "comparison_oracle", lambda: True)
    monkeypatch.setattr(claims, "header_walk", lambda: True)
    assert claims.main() == 0
