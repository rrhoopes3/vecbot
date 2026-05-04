from vecbot.analyzer import analyze
from vecbot.capabilities import CapabilityBaseline
from vecbot.scenarios import scenario_events


def clean_baseline():
    return CapabilityBaseline.learn([scenario_events("clean")])


def test_clean_scenario_has_no_findings_or_residue():
    result = analyze(scenario_events("clean"), clean_baseline())

    assert result.findings == []
    assert result.residue == {}


def test_runtime_shell_is_reported_as_package_phase_capability_drift():
    result = analyze(scenario_events("malicious-runtime"), clean_baseline())

    assert any(
        finding.package == "markdown-theme-helper"
        and finding.phase == "STEADY_RUN"
        and finding.capability == "proc.spawn"
        and finding.primary_signal
        for finding, _event in result.findings
    )
    assert result.residue["child_processes"] == ["/bin/sh"]


def test_persistence_residue_is_critical():
    result = analyze(scenario_events("persistence-residue"), clean_baseline())

    assert any(finding.severity == "critical" for finding, _event in result.findings)
    assert result.residue["persistence_files"] == ["~/.config/autostart/helper.desktop"]

