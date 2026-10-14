from agent.llm import OpenRouterLLMClient


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_openrouter_decide_uses_bearer_key_and_parses_json():
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({
            "choices": [{"message": {"content": '{"hypothesis":"inspect files","command":"ls -la"}'}}]
        })

    decision = OpenRouterLLMClient(
        "test-key", "vendor/model", post_func=fake_post
    ).decide("level data")

    assert decision.command == "ls -la"
    assert calls[0][0].endswith("/chat/completions")
    assert calls[0][1]["headers"]["Authorization"] == "Bearer test-key"
    assert calls[0][1]["json"]["model"] == "vendor/model"


def test_openrouter_model_check_uses_model_metadata_endpoint():
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"data": {"name": "Example model"}})

    data = OpenRouterLLMClient(
        "test-key", "vendor/model", get_func=fake_get
    ).check_model()

    assert data["name"] == "Example model"
    assert calls[0][0].endswith("/model/vendor/model")
    assert calls[0][1]["headers"]["Authorization"] == "Bearer test-key"
