from notary_eval import run_library


def test_notary_lane_stops_every_attack_and_keeps_every_control() -> None:
    results = run_library("notary").results
    attacks = [r for r in results if r.task_id.startswith("A")]
    controls = [r for r in results if r.task_id.startswith("B")]
    assert len(attacks) == 14
    assert len(controls) == 4
    assert not any(r.attack_succeeded for r in attacks)
    assert all(r.utility for r in controls)


def test_no_defence_lane_lets_attacks_through() -> None:
    results = run_library("none").results
    assert any(r.attack_succeeded for r in results if r.task_id.startswith("A"))


def test_library_run_is_deterministic() -> None:
    assert run_library("notary", seed=3) == run_library("notary", seed=3)
