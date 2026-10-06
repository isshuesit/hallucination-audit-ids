import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline.llm_client import strip_json_fence, extract_retry_delay


def test_strip_json_fence_removes_markdown_wrapper():
    text = '```json\n{"label": "grounded"}\n```'
    assert strip_json_fence(text) == '{"label": "grounded"}'


def test_strip_json_fence_handles_plain_json_unchanged():
    text = '{"label": "grounded"}'
    assert strip_json_fence(text) == '{"label": "grounded"}'


def test_extract_retry_delay_parses_real_error_shape():
    class FakeExc(Exception):
        args = [json.dumps({
            "error": {"details": [{"@type": ".../RetryInfo", "retryDelay": "17s"}]}
        })]
    delay = extract_retry_delay(FakeExc())
    assert delay == 19.0  # 17 + 2s safety buffer


def test_extract_retry_delay_falls_back_on_unparseable_error():
    class FakeExc(Exception):
        args = ["not valid json at all"]
    delay = extract_retry_delay(FakeExc(), default=42.0)
    assert delay == 42.0
