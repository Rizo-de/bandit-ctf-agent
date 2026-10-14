import httpx
from agent.llm import OpenRouterLLMClient, OpenRouterRateLimitError
import pytest


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
    assert calls[0][1]["json"]["max_completion_tokens"] == 4096


def test_openrouter_reports_when_reasoning_uses_the_entire_completion_budget():
    def fake_post(url, **kwargs):
        return FakeResponse({
            "choices": [{
                "finish_reason": "length",
                "message": {"content": "", "reasoning": "not shown"},
            }],
            "usage": {
                "completion_tokens": 1024,
                "completion_tokens_details": {"reasoning_tokens": 1024},
            },
        })

    client = OpenRouterLLMClient("test-key", "vendor/model", post_func=fake_post)

    with pytest.raises(ValueError, match="finish_reason=length.*reasoning_tokens=1024"):
        client.decide("level data")


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


def test_openrouter_429_is_reported_with_retry_after_without_response_body():
    def fake_post(url, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(
            429,
            headers={"Retry-After": "30"},
            text="private provider details",
            request=request,
        )

    client = OpenRouterLLMClient("test-key", "vendor/model", post_func=fake_post)

    with pytest.raises(OpenRouterRateLimitError, match="mindestens 30 Sekunden") as error:
        client.decide("level data")

    assert error.value.retry_after == 30
    assert "private provider details" not in str(error.value)
