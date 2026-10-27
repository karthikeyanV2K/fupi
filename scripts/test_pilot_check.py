"""Unit tests for scripts/pilot_check.py (pure evaluate())."""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pilot_check import FAIL, WARN, evaluate  # noqa: E402

GOOD = {"reserve": 460, "issued_outstanding": 93, "deposits_total": 500, "deposit_count": 2,
        "settled_count": 19, "devices_allocated": 300, "devices_loaded": 241, "settled_total": 148,
        "paid_total": 40, "owed_total": 108, "fully_backed": True, "ledger_consistent": True}
REPORT = {"entries": [{"amount": 148}], "merchants": [
    {"merchant": "a", "settled": 100, "paid": 40, "owed": 60}, {"merchant": "b", "settled": 48, "paid": 0, "owed": 48}]}


def levels(res):
    return {lvl for lvl, _ in res}


def test_healthy_state_passes():
    assert FAIL not in levels(evaluate(GOOD, bank=460, max_total=500, report=REPORT))


def test_kiosk_flags_fail():
    for key in ("fully_backed", "ledger_consistent"):
        rc = dict(GOOD, **{key: False})
        assert FAIL in levels(evaluate(rc, bank=460, report=REPORT))


def test_bank_below_reserve_is_a_failure_above_is_a_warning():
    assert FAIL in levels(evaluate(GOOD, bank=459.0, report=REPORT))
    res = evaluate(GOOD, bank=470, report=REPORT)
    assert WARN in levels(res) and FAIL not in levels(res)
    assert WARN in levels(evaluate(GOOD, report=REPORT))  # no bank balance given


def test_pilot_cap_and_device_quota():
    assert FAIL in levels(evaluate(GOOD, bank=460, max_total=250, report=REPORT))
    assert FAIL in levels(evaluate(dict(GOOD, devices_loaded=301), bank=460, report=REPORT))


def test_rollback_is_detected():
    prev = copy.deepcopy(GOOD)
    rolled = dict(GOOD, settled_count=10, settled_total=100)  # spent set shrank
    assert FAIL in levels(evaluate(rolled, prev=prev, bank=460))
    assert FAIL in levels(evaluate(dict(GOOD, deposits_total=400, reserve=360), prev=prev, bank=360))


def test_reserve_moves_must_be_explained():
    prev = dict(GOOD, reserve=400, deposits_total=440, paid_total=40)
    # +60 reserve and +60 deposits: fine
    assert FAIL not in levels(evaluate(GOOD, prev=prev, bank=460, report=REPORT))
    # reserve grew with no deposit behind it
    assert FAIL in levels(evaluate(dict(GOOD, deposits_total=440), prev=prev, bank=460))


def test_settlement_log_must_match_reconcile():
    short = {"entries": [{"amount": 100}], "merchants": REPORT["merchants"]}
    assert FAIL in levels(evaluate(GOOD, bank=460, report=short))
    bad = {"entries": REPORT["entries"], "merchants": [{"merchant": "a", "settled": 100, "paid": 40, "owed": 99}]}
    assert FAIL in levels(evaluate(GOOD, bank=460, report=bad))


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"{len(fns)} passed, 0 failed")
