import json

from agent.password_store import load_passwords, save_passwords


def test_password_store_round_trips_bandit_credentials_outside_project(tmp_path):
    target = tmp_path / ".bandit_agent" / "passwords.json"
    stored_path = save_passwords(
        {"bandit1": "verified-example", "not-a-bandit-user": "ignore"},
        path=target,
    )

    assert stored_path == target
    assert load_passwords(target) == {"bandit1": "verified-example"}
    assert json.loads(target.read_text(encoding="utf-8")) == {
        "bandit1": "verified-example"
    }


def test_password_store_returns_empty_for_missing_or_corrupt_file(tmp_path):
    target = tmp_path / "passwords.json"
    assert load_passwords(target) == {}
    target.write_text("not-json", encoding="utf-8")
    assert load_passwords(target) == {}
