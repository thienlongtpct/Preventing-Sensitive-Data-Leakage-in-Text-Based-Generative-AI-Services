import json
import statistics

import pytest

from privacy_gateway.audit.sanitize import sanitize_event
from privacy_gateway.audit.store import GENESIS, KEY_ENV, AuditStore, event_digest
from privacy_gateway.factory import load_config
from privacy_gateway.privacy.__main__ import main
from privacy_gateway.privacy.accountant import BudgetExceeded, PrivacyAccountant
from privacy_gateway.privacy.benchmark import format_summary, run_benchmark, synthetic_events
from privacy_gateway.privacy.differential import noisy_counts
from privacy_gateway.privacy.homomorphic import Aggregator, GatewayEncryptor, KeyHolder, he_backend, secure_sum
from privacy_gateway.privacy.reporting import (
    DEFAULT_STATISTICS,
    allocate_budget,
    build_privacy_report,
    publish_report,
    release,
)
from privacy_gateway.privacy.risk import CATEGORIES, RiskLayout, split_batches
from privacy_gateway.schemas import ACTION_RANK, Request

EVENT = {
    "role": "guest",
    "service": "chat",
    "action": "block",
    "categories": ["secret"],
    "risk_score": 1.0,
    "warnings": [],
}
ROLES = load_config()["roles"]
needs_tenseal = pytest.mark.skipif(he_backend() != "tenseal-ckks", reason="TenSEAL not installed")


@pytest.fixture(autouse=True)
def no_audit_key(monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)


def _store(tmp_path, count=4, key=None):
    store = AuditStore(tmp_path / "audit.jsonl", key=key)
    for position in range(count):
        store.append({**EVENT, "risk_score": (position + 1) / count})
    return store


def _lines(store):
    return store.path.read_text(encoding="utf-8").splitlines()


def _write(store, lines):
    store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_sanitize_keeps_only_fixed_vocabulary():
    event = sanitize_event(
        {
            "role": "Contractor SSN 123-45-6789",
            "service": "email",
            "action": "block",
            "categories": ["secret", "made_up"],
            "risk_score": 3,
            "warnings": ["Removed restricted context E-1001.", "pii detected (medium).", "card 4111"],
            "text": "My SSN is 123-45-6789",
            "ts": "2026-10-26T15:42:37.123456+00:00",
        }
    )
    assert event["role"] == "invalid"
    assert event["service"] == "invalid"
    assert event["categories"] == ["secret"]
    assert event["risk_score"] == 1.0
    assert event["warnings"] == ["context_removed", "other", "warn:pii:medium"]
    assert event["ts"] == "2026-10-26T15:42:00+00:00"
    assert "text" not in event
    assert "123-45-6789" not in json.dumps(event)


def test_gateway_audit_drops_record_ids_and_stays_chained(gateway):
    for role, service, text in (
        ("guest", "agent", "Pull record C-9 for the ticket."),
        ("guest", "rag", "What time does the office open? Also E-1001 details"),
    ):
        result = gateway.handle(Request(text, role, service))
        assert any(warning.startswith("Removed restricted context") for warning in result.warnings)
    log = gateway.audit.path.read_text(encoding="utf-8")
    assert "C-9" not in log
    assert "E-1001" not in log
    assert "context_removed" in log
    assert gateway.audit.verify().ok


@pytest.mark.parametrize("attack", ["edit", "delete", "swap", "insert"])
def test_chain_detects_tampering(tmp_path, attack):
    store = _store(tmp_path)
    assert store.verify().ok
    lines = _lines(store)
    if attack == "edit":
        event = json.loads(lines[1])
        event["risk_score"] = 0.0
        lines[1] = json.dumps(event, sort_keys=True)
    elif attack == "delete":
        del lines[1]
    elif attack == "swap":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines.insert(2, lines[1])
    _write(store, lines)
    check = store.verify()
    assert not check.ok
    assert check.first_bad in {2, 3}


def test_keyed_chain_survives_a_rehash_that_fools_plain_sha256(tmp_path):
    store = _store(tmp_path, key="audit-key")
    prev_hash, forged = GENESIS, []
    for line in _lines(store):
        event = json.loads(line)
        event["risk_score"] = 0.0
        event["prev_hash"] = prev_hash
        event["hash"] = event_digest(event)
        prev_hash = event["hash"]
        forged.append(json.dumps(event, sort_keys=True))
    _write(store, forged)
    assert AuditStore(store.path).verify().ok
    assert not store.verify().ok


def test_wrong_key_fails(tmp_path):
    store = _store(tmp_path, key="right")
    assert store.verify().ok
    assert not AuditStore(store.path, key="wrong").verify().ok


def test_anchor_catches_a_cut_off_tail(tmp_path):
    store = _store(tmp_path, count=5)
    anchor = store.head()
    _write(store, _lines(store)[:3])
    assert store.verify().ok
    assert not store.verify(anchor).ok


def test_head_reads_past_the_first_block(tmp_path):
    store = _store(tmp_path, count=300)
    assert store.head()[0] == 300
    assert store.verify().ok


def test_seeded_noise_repeats():
    assert noisy_counts({"a": 5, "b": 1}, 1.0, seed=3) == noisy_counts({"a": 5, "b": 1}, 1.0, seed=3)


def test_noise_scale_follows_sensitivity():
    for sensitivity in (1.0, 5.0):
        draws = [
            abs(noisy_counts({"a": 1000.0}, 1.0, seed=seed, sensitivity=sensitivity)["a"] - 1000.0)
            for seed in range(2000)
        ]
        assert statistics.fmean(draws) == pytest.approx(sensitivity, rel=0.15)


def test_one_event_stays_inside_declared_sensitivity():
    layout = RiskLayout()
    worst = {**EVENT, "categories": list(CATEGORIES), "role": "nobody", "service": "fax"}
    for event in synthetic_events(500, ROLES, seed=1) + [worst]:
        vector = layout.decode(layout.encode(event))
        for slots, sensitivity in layout.statistics.values():
            assert sum(abs(vector[slot]) for slot in slots) <= sensitivity + 1e-9


def test_category_cap_keeps_most_severe():
    layout = RiskLayout(max_categories=2)
    event = {**EVENT, "categories": ["pii", "secret", "retrieval", "memorized"]}
    assert layout.capped_categories(event) == ["secret", "memorized"]
    assert layout.statistics["categories"][1] == 2


def test_budget_split_adds_up_and_equalizes_noise():
    layout = RiskLayout()
    allocation = allocate_budget(layout, 2.0, DEFAULT_STATISTICS)
    assert sum(allocation.values()) == pytest.approx(2.0)
    _, noise = release(layout.decode(layout.total([EVENT])), layout, 2.0, seed=1)
    assert len({row["noise_scale"] for row in noise}) == 1
    with pytest.raises(ValueError):
        allocate_budget(layout, 1.0, ("events", "nonsense"))


def test_accountant_refuses_and_persists(tmp_path):
    ledger = tmp_path / "ledger.json"
    accountant = PrivacyAccountant(1.0, ledger)
    accountant.spend(0.6, "first")
    with pytest.raises(BudgetExceeded):
        accountant.spend(0.5, "second")
    reloaded = PrivacyAccountant(50.0, ledger)
    assert reloaded.total_epsilon == 1.0
    assert reloaded.remaining == pytest.approx(0.4)
    reloaded.spend(0.4, "third")
    assert reloaded.remaining == pytest.approx(0.0)


def test_publish_report_charges_budget_and_hides_exact_values(tmp_path):
    accountant = PrivacyAccountant(1.0, tmp_path / "ledger.json")
    batches = [[EVENT] * 10, [{**EVENT, "role": "admin", "action": "redact"}] * 5]
    report = publish_report(batches, 1.0, accountant=accountant, seed=1)
    assert set(report) == {
        "epsilon",
        "dp_backend",
        "aggregation",
        "unit",
        "max_categories_per_event",
        "noise",
        "risk",
        "warnings",
        "budget",
    }
    assert report["aggregation"]["parties"] == 2
    assert report["budget"]["remaining"] == pytest.approx(0.0)
    assert report["warnings"]
    with pytest.raises(BudgetExceeded):
        publish_report(batches, 0.1, accountant=accountant)
    assert len(accountant.spends) == 1


def test_build_privacy_report_keeps_harness_fields():
    report = build_privacy_report([EVENT] * 4, epsilon=1.0, seed=2)
    assert report["events"] == 4
    assert report["homomorphic_risk"]["count"] == 4
    assert report["homomorphic_risk"]["sum"] == pytest.approx(4.0, abs=1e-4)
    assert set(report["differential_privacy"]["actions"]) == set(ACTION_RANK)


def test_secure_sum_matches_plaintext():
    layout = RiskLayout()
    events = synthetic_events(300, ROLES, seed=4)
    batches = split_batches(events, 4)
    result = secure_sum([layout.total(batch) for batch in batches])
    assert result.parties == 4
    assert result.totals == pytest.approx(layout.total(events), abs=1e-4)
    fallback = secure_sum([[1.0, 2.0], [3.0, 4.0]], encrypted=False)
    assert fallback.backend == "plaintext-fallback"
    assert fallback.totals == [4.0, 6.0]


@needs_tenseal
def test_only_the_key_holder_can_decrypt():
    import tenseal as ts

    holder = KeyHolder()
    public = holder.public_context()
    first = GatewayEncryptor(public).encrypt([1.0, 2.0])
    second = GatewayEncryptor(public).encrypt([0.5, 0.5])
    with pytest.raises(ValueError):
        ts.ckks_vector_from(ts.context_from(public), first).decrypt()
    total = Aggregator(public).add([first, second])
    assert holder.decrypt(total)[:2] == pytest.approx([1.5, 2.5], abs=1e-4)


@needs_tenseal
def test_parties_refuse_a_context_with_the_secret_key():
    holder = KeyHolder()
    private = holder._context.serialize(save_secret_key=True)
    with pytest.raises(ValueError):
        GatewayEncryptor(private)
    with pytest.raises(ValueError):
        Aggregator(private)


def test_demo_catches_every_attack_and_stops_at_budget(capsys):
    assert main(["demo", "--events", "40"]) == 0
    output = capsys.readouterr().out
    assert "MISSED" not in output
    assert output.count("caught") == 4
    assert "release 3: refused" in output
    assert "Prompts or labeled secrets found in the logs: 0." in output


def test_benchmark_summary_has_every_section():
    summary = format_summary(run_benchmark(ROLES, trials=2))
    for heading in ("Error vs epsilon", "Category cap", "Encrypted aggregation"):
        assert heading in summary
