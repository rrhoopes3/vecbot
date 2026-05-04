from vecbot.events import normalize


def test_normalize_preserves_attribution_and_phase_hint():
    event = normalize(
        {
            "ts": 1,
            "pid": 7,
            "tid": 8,
            "phase_hint": "INIT_IMPORT",
            "action": "connect",
            "target": "example.test:443",
            "package": "demo",
            "attribution_source": "python_stack",
            "attribution_confidence": 0.85,
            "fd": 3,
        }
    )

    assert event.phase_hint == "INIT_IMPORT"
    assert event.tid == 8
    assert event.capability == "net.outbound"
    assert event.attribution_source == "python_stack"
    assert event.attribution_confidence == 0.85
    assert event.fd == 3

