import json

from vecbot.capabilities import BASELINE_SCHEMA_VERSION, CapabilityBaseline
from vecbot.scenarios import scenario_events


def test_baseline_round_trip(tmp_path):
    output = tmp_path / "baseline.json"
    baseline = CapabilityBaseline.learn(
        [scenario_events("clean")],
        sources=["clean.jsonl"],
    )

    baseline.save(output)
    loaded = CapabilityBaseline.load(output)

    assert loaded.sources == ["clean.jsonl"]
    assert loaded.has_capability("requests", "STEADY_RUN", "net.outbound")
    assert loaded.phase_distribution("STEADY_RUN") == baseline.phase_distribution("STEADY_RUN")


def test_baseline_schema_is_explicit(tmp_path):
    output = tmp_path / "baseline.json"
    CapabilityBaseline.learn([scenario_events("clean")]).save(output)

    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["schema_version"] == BASELINE_SCHEMA_VERSION
    assert "created_at" in payload
    assert "package_phase_capabilities" in payload
    assert "phase_histograms" in payload
