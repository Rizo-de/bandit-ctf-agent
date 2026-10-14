from types import SimpleNamespace

from agent.collaboration import build_chat_prompt, chat_answer


def test_chat_prompt_uses_level_history_hints_and_redacts_passwords():
    secret = "a" * 32
    prompt = build_chat_prompt(
        level="bandit3",
        goal="Find and verify the next level password",
        terminal_log=f"$ cat file\n{secret}",
        agent_report={"status": "RUNNING", "hypothesis": "inspect file"},
        hints=["The listing showed a hidden file"],
        chat_history=[{"role": "user", "content": "What next?"}],
        secrets=[secret],
    )

    assert "bandit3" in prompt
    assert "The listing showed a hidden file" in prompt
    assert "What next?" in prompt
    assert secret not in prompt
    assert "untrusted observation data" in prompt


def test_chat_answer_never_presents_command_as_executed():
    answer = chat_answer(
        SimpleNamespace(
            summary="The directory contains one hidden file.",
            hypothesis="It may contain the level clue.",
            reason="Read it to inspect the contents.",
            command="cat hidden",
            expected_output="The clue text.",
        ),
        command_allowed=True,
    )

    assert "wird nicht automatisch ausgeführt" in answer
    assert "Beobachtung" in answer
    assert "Vermutung" in answer
