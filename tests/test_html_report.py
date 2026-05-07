from vecbot.analyzer import analyze
from vecbot.capabilities import CapabilityBaseline
from vecbot.html_report import render_html_report
from vecbot.scenarios import scenario_events


def test_html_report_contains_findings_residue_and_timeline():
    baseline = CapabilityBaseline.learn([scenario_events("clean")])
    result = analyze(scenario_events("malicious-runtime"), baseline)

    html = render_html_report("malicious-runtime", result)

    assert "<!doctype html>" in html
    assert "VecBot Report" in html
    assert "markdown-theme-helper gained proc.spawn" in html
    assert "Residue" in html
    assert "8:198.51.100.7:443" in html
    assert "Event Timeline" in html


def test_html_report_escapes_trace_content():
    baseline = CapabilityBaseline.learn([scenario_events("clean")])
    events = scenario_events("malicious-runtime")
    events[3].target = "<script>alert(1)</script>"

    html = render_html_report("xss-check", analyze(events, baseline))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
