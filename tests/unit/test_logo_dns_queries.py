"""LogoDNSQueries loader: curated fixtures and sidecar ground truth."""

from __future__ import annotations

from pathlib import Path

from app.constants.logo_dns import SCENARIO_NAME
from app.domain.enums import ThreatType
from simulator.logo_dns_queries import LogoDNSQueries


def test_curated_fixtures_cover_each_family_with_a_negative() -> None:
    samples = LogoDNSQueries().load_curated()
    by_threat = LogoDNSQueries.report(samples)
    assert by_threat[ThreatType.DGA.value] >= 1
    assert by_threat[ThreatType.TYPOSQUATTING.value] >= 1
    assert by_threat[ThreatType.DNS_TUNNELING.value] >= 1
    assert by_threat[ThreatType.BEACONING.value] >= 1
    assert by_threat[ThreatType.NONE.value] >= 1
    techniques = {sample.technique for sample in samples}
    assert "benign_dictionary" in techniques or "authorized_brand" in techniques
    assert "nxdomain_qoe" in techniques
    assert any(sample.source_path.endswith(".csv") for sample in samples)
    assert any(sample.source_path.endswith(".json") for sample in samples)
    assert any(sample.source_path.endswith(".jsonl") for sample in samples)


def test_events_never_include_ground_truth_fields() -> None:
    sample = LogoDNSQueries().load_curated()[0]
    dumped = sample.event.model_dump()
    assert "threat_type" not in dumped
    assert "technique" not in dumped
    assert "ground_truth" not in dumped
    assert sample.event.synthetic is True
    assert sample.event.schema_version == "1.0"
    sidecar = LogoDNSQueries().labels(sample)
    assert sidecar["threat_type"] == sample.threat_type
    assert sidecar["scenario"] == sample.scenario


def test_event_ids_are_stable_for_the_same_row() -> None:
    first = LogoDNSQueries().load_curated()
    second = LogoDNSQueries().load_curated()
    assert [item.event.event_id for item in first] == [item.event.event_id for item in second]


def test_discovers_csv_json_jsonl_from_source_directory(tmp_path: Path) -> None:
    (tmp_path / "ignored.txt").write_text("nope", encoding="utf-8")
    (tmp_path / "one.jsonl").write_text(
        '{"qname":"xkqpwzlmntabvdfg.test","qtype":"A","rcode":"NXDOMAIN","threat_type":"dga"}\n',
        encoding="utf-8",
    )
    (tmp_path / "two.json").write_text(
        '{"qname":"portal.northwind.test","qtype":"A","threat_type":"none"}\n',
        encoding="utf-8",
    )
    (tmp_path / "three.csv").write_text(
        "domain,type,rcode,threat_type\nacmebunk.test,A,NOERROR,typosquatting\n",
        encoding="utf-8",
    )
    loader = LogoDNSQueries(source_dir=tmp_path, fixtures_dir=tmp_path / "missing")
    names = {path.name for path in loader.discover()}
    assert names == {"one.jsonl", "two.json", "three.csv"}
    samples = loader.load()
    threats = {sample.threat_type for sample in samples}
    qnames = {sample.event.qname for sample in samples}
    assert threats == {"dga", "none", "typosquatting"}
    assert "xkqpwzlmntabvdfg.test" in qnames
    assert "acmebunk.test" in qnames


def test_skips_non_synthetic_rows(tmp_path: Path) -> None:
    (tmp_path / "rows.jsonl").write_text(
        '{"qname":"real.example.test","synthetic":false,"threat_type":"dga"}\n'
        '{"qname":"ok.example.test","synthetic":true,"threat_type":"none"}\n',
        encoding="utf-8",
    )
    samples = LogoDNSQueries(source_dir=tmp_path, fixtures_dir=tmp_path / "none").load()
    assert len(samples) == 1
    assert samples[0].event.qname == "ok.example.test"
    assert samples[0].event.synthetic is True


def test_stratified_take_covers_multiple_labels() -> None:
    samples = LogoDNSQueries().load_curated()
    picked = LogoDNSQueries().take_stratified(samples, 6)
    labels = {item.threat_type for item in picked}
    assert len(picked) == 6
    assert ThreatType.DGA.value in labels
    assert ThreatType.NONE.value in labels
    assert SCENARIO_NAME == "logo_dns"
