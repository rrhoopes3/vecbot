"""Self-contained HTML reports for VecBot analyses."""

from __future__ import annotations

from html import escape

from vecbot.render import snake_view


def render_html_report(name: str, result) -> str:
    finding_by_event_id = {id(event): finding for finding, event in result.findings}
    finding_cards = "\n".join(
        _finding_card(finding, event) for finding, event in result.findings
    ) or '<p class="quiet">No interesting phase capability drift detected.</p>'
    residue = _residue_block(result.residue)
    events = "\n".join(
        _event_row(phase, event, finding_by_event_id.get(id(event)))
        for phase, event in result.events
    )
    phase_counts = _phase_counts(result.events)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VecBot Report - {escape(name)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #19202a;
      --muted: #687385;
      --line: #d8dee8;
      --accent: #116d6e;
      --warn: #9b4d00;
      --bad: #b3261e;
      --critical: #701313;
      --ok: #2f6d3a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 28px auto 48px;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 16px;
      align-items: end;
      margin-bottom: 20px;
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{ font-size: 28px; letter-spacing: 0; }}
    h2 {{ font-size: 17px; margin-bottom: 10px; letter-spacing: 0; }}
    h3 {{ font-size: 15px; margin-bottom: 6px; letter-spacing: 0; }}
    code, .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }}
    .subtle {{ color: var(--muted); margin-top: 4px; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 20px;
    }}
    .metric, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(20, 30, 45, 0.04);
    }}
    .metric {{ padding: 12px; }}
    .metric .label {{ color: var(--muted); font-size: 12px; }}
    .metric .value {{ font-size: 24px; font-weight: 700; margin-top: 2px; }}
    section {{ padding: 16px; margin-bottom: 14px; }}
    .phase-strip {{
      display: grid;
      grid-template-columns: repeat({max(len(phase_counts), 1)}, minmax(0, 1fr));
      gap: 8px;
    }}
    .phase {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      background: #fbfcfe;
    }}
    .phase strong {{ display: block; margin-bottom: 3px; }}
    .finding {{
      border-left: 4px solid var(--bad);
      padding: 10px 12px;
      background: #fff8f7;
      border-radius: 6px;
      margin-bottom: 8px;
    }}
    .finding.critical {{ border-left-color: var(--critical); background: #fff4f4; }}
    .finding.high {{ border-left-color: var(--bad); }}
    .finding.medium {{ border-left-color: var(--warn); background: #fffaf2; }}
    .evidence {{ color: var(--muted); margin-top: 4px; }}
    .snake {{
      display: inline-block;
      margin-top: 8px;
      padding: 6px 8px;
      background: #eef7f7;
      border: 1px solid #c9e1e0;
      border-radius: 6px;
      color: var(--accent);
      white-space: nowrap;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 8px 6px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 600; }}
    tr.alert td {{ background: #fff8f7; }}
    .pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 7px;
      background: #eef1f5;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .pill.high, .pill.critical {{ background: #ffe1df; color: var(--bad); }}
    .pill.medium {{ background: #fff0d6; color: var(--warn); }}
    .quiet {{ color: var(--ok); }}
    .residue {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }}
    .residue-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px;
      background: #fbfcfe;
    }}
    @media (max-width: 760px) {{
      header, .summary, .phase-strip, .residue {{ grid-template-columns: 1fr; }}
      main {{ width: min(100% - 20px, 1120px); margin-top: 16px; }}
      table {{ table-layout: auto; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>VecBot Report</h1>
        <p class="subtle mono">{escape(name)}</p>
      </div>
      <div class="pill">{escape(result.final_phase)}</div>
    </header>

    <div class="summary">
      <div class="metric"><div class="label">Events</div><div class="value">{len(result.events)}</div></div>
      <div class="metric"><div class="label">Findings</div><div class="value">{len(result.findings)}</div></div>
      <div class="metric"><div class="label">Residue Types</div><div class="value">{len(result.residue)}</div></div>
      <div class="metric"><div class="label">Phases</div><div class="value">{len(phase_counts)}</div></div>
    </div>

    <section>
      <h2>Phase Shape</h2>
      <div class="phase-strip">
        {_phase_cards(phase_counts)}
      </div>
    </section>

    <section>
      <h2>Findings</h2>
      {finding_cards}
    </section>

    <section>
      <h2>Residue</h2>
      {residue}
    </section>

    <section>
      <h2>Event Timeline</h2>
      <table>
        <thead>
          <tr>
            <th style="width: 72px;">Time</th>
            <th style="width: 118px;">Phase</th>
            <th style="width: 170px;">Package</th>
            <th style="width: 170px;">Capability</th>
            <th>Target</th>
            <th style="width: 90px;">Signal</th>
          </tr>
        </thead>
        <tbody>
          {events}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


def _phase_counts(events: list[tuple[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for phase, _event in events:
        counts[phase] = counts.get(phase, 0) + 1
    return counts


def _phase_cards(counts: dict[str, int]) -> str:
    if not counts:
        return '<p class="quiet">No events.</p>'
    return "\n".join(
        f'<div class="phase"><strong>{escape(phase)}</strong><span class="subtle">{count} events</span></div>'
        for phase, count in counts.items()
    )


def _finding_card(finding, event) -> str:
    severity = escape(finding.severity)
    reasons = "; ".join(escape(reason) for reason in finding.reasons)
    return f"""<article class="finding {severity}">
  <h3>{escape(finding.package)} gained {escape(finding.capability)}</h3>
  <p class="mono">{escape(finding.phase)} -> {escape(event.target)}</p>
  <p class="evidence">{reasons}</p>
  <span class="snake mono">{escape(snake_view(finding.phase, [finding.capability], finding.drift))}</span>
</article>"""


def _residue_block(residue: dict[str, list[str]]) -> str:
    if not residue:
        return '<p class="quiet">No residue detected.</p>'
    items = []
    for key, values in residue.items():
        safe_values = ", ".join(escape(value) for value in values)
        items.append(
            f'<div class="residue-item"><strong>{escape(key)}</strong><p class="mono subtle">{safe_values}</p></div>'
        )
    return f'<div class="residue">{"".join(items)}</div>'


def _event_row(phase: str, event, finding) -> str:
    row_class = "alert" if finding else ""
    signal = ""
    if finding:
        signal = f'<span class="pill {escape(finding.severity)}">{escape(finding.severity)}</span>'
    return f"""<tr class="{row_class}">
  <td class="mono">{event.ts:.2f}</td>
  <td>{escape(phase)}</td>
  <td>{escape(event.package or "unknown")}</td>
  <td>{escape(event.capability)}</td>
  <td class="mono">{escape(event.target)}</td>
  <td>{signal}</td>
</tr>"""
