import paramiko
import pytest

from agent.host_keys import host_key_fingerprint, save_bandit_host_key


def test_approved_bandit_key_is_saved_for_the_nonstandard_port(tmp_path):
    key = paramiko.RSAKey.generate(1024)
    path = tmp_path / ".ssh" / "known_hosts"

    saved_path = save_bandit_host_key(
        "bandit.labs.overthewire.org", 2220, key, known_hosts_path=path
    )

    loaded = paramiko.HostKeys(str(path))
    entry = loaded.lookup("[bandit.labs.overthewire.org]:2220")
    assert saved_path == path
    assert entry is not None
    assert entry[key.get_name()] == key
    assert host_key_fingerprint(key).startswith("SHA256:")


def test_changed_bandit_key_is_not_silently_replaced(tmp_path):
    path = tmp_path / ".ssh" / "known_hosts"
    first = paramiko.RSAKey.generate(1024)
    changed = paramiko.RSAKey.generate(1024)
    save_bandit_host_key("bandit.labs.overthewire.org", 2220, first, known_hosts_path=path)

    with pytest.raises(ValueError, match="weicht ab"):
        save_bandit_host_key("bandit.labs.overthewire.org", 2220, changed, known_hosts_path=path)

    loaded = paramiko.HostKeys(str(path))
    assert loaded.lookup("[bandit.labs.overthewire.org]:2220")[first.get_name()] == first


@pytest.mark.parametrize(
    ("host", "port"),
    [("example.org", 2220), ("bandit.labs.overthewire.org", 22)],
)
def test_host_key_pinning_is_restricted_to_the_authorized_bandit_endpoint(tmp_path, host, port):
    key = paramiko.RSAKey.generate(1024)

    with pytest.raises(ValueError, match="nur für"):
        save_bandit_host_key(host, port, key, known_hosts_path=tmp_path / "known_hosts")
