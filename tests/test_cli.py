import json

from vecbot.cli import main


def test_learn_and_analyze_with_json_output(tmp_path, capsys):
    trace = tmp_path / "malicious-runtime.jsonl"
    baseline = tmp_path / "baseline.json"

    main(["simulate", "clean"])
    clean_trace = tmp_path / "clean.jsonl"
    clean_trace.write_text(capsys.readouterr().out, encoding="utf-8")

    main(["simulate", "malicious-runtime"])
    trace.write_text(capsys.readouterr().out, encoding="utf-8")

    assert main(["learn", str(clean_trace), "--out", str(baseline)]) == 0
    capsys.readouterr()

    assert main(["analyze", str(trace), "--baseline", str(baseline), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["finding_count"] == 2
    assert payload["residue"]["child_processes"] == ["/bin/sh"]
    assert payload["findings"][0]["finding"]["package"] == "markdown-theme-helper"


def test_trace_reader_accepts_powershell_utf16_redirection(tmp_path, capsys):
    trace = tmp_path / "clean.utf16.jsonl"
    baseline = tmp_path / "baseline.json"

    main(["simulate", "clean"])
    trace.write_text(capsys.readouterr().out, encoding="utf-16")

    assert main(["learn", str(trace), "--out", str(baseline)]) == 0
    assert baseline.exists()


def test_report_command_writes_html(tmp_path, capsys):
    output = tmp_path / "report.html"

    assert main(["report", "--scenario", "malicious-runtime", "--out", str(output)]) == 0
    text = output.read_text(encoding="utf-8")

    assert "wrote report:" in capsys.readouterr().out
    assert "VecBot Report" in text
    assert "markdown-theme-helper gained proc.spawn" in text
