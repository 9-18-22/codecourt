import json
from types import SimpleNamespace

import pytest

import pipeline.llm_generator as lg


class FakeAdapter:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.prompts = []

    def call(self, system_prompt, user_prompt):
        self.calls += 1
        self.prompts.append(user_prompt)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def report():
    return SimpleNamespace(
        id="unit:test:1",
        bug_type="NULL_DEREFERENCE",
        qualifier="p may be null",
        file="sample.c",
        line=10,
        procedure="foo",
        source_code="int foo(int *p) { return *p; }",
        trace_as_text=lambda: "line 10: dereference p",
    )


def response(confidence="high", input_type="args", args=None, expected="SEGV"):
    return json.dumps({
        "reasoning": "test reasoning",
        "input_type": input_type,
        "args": [] if args is None else args,
        "stdin_data": "",
        "file_inputs": {},
        "env_vars": {},
        "expected_crash": expected,
        "confidence": confidence,
        "needs_instrumentation": False,
        "instrumentation_code": None,
    })


def make_generator(monkeypatch, responses):
    adapter = FakeAdapter(responses)
    monkeypatch.setattr(lg, "_build_adapter", lambda: adapter)
    monkeypatch.setattr(lg.config, "max_retries", 3, raising=False)
    monkeypatch.setattr(lg.time, "sleep", lambda _: None)
    gen = lg.LLMGenerator()
    return gen, adapter


def test_low_confidence_triggers_regeneration(monkeypatch):
    gen, adapter = make_generator(monkeypatch, [
        response(confidence="low", input_type="none", args=[], expected=""),
        response(confidence="high", input_type="args", args=["--crash"]),
    ])

    result = gen.generate(report())

    assert adapter.calls == 2
    assert result.confidence == "high"
    assert result.args == ["--crash"]


def test_all_low_confidence_runs_max_attempts_then_returns_best(monkeypatch):
    gen, adapter = make_generator(monkeypatch, [
        response(confidence="low", input_type="none", args=[], expected=""),
        response(confidence="low", input_type="none", args=[], expected=""),
        response(confidence="low", input_type="none", args=[], expected=""),
    ])

    result = gen.generate(report())

    assert adapter.calls == 3
    assert result.confidence == "low"
    assert result.input_type == "none"


def test_parse_failure_retries_llm_call(monkeypatch):
    gen, adapter = make_generator(monkeypatch, [
        "not json",
        response(confidence="medium", input_type="args", args=["1"]),
    ])

    result = gen.generate(report())

    assert adapter.calls == 2
    assert result.confidence == "medium"
    assert result.args == ["1"]


def test_api_error_retries_llm_call(monkeypatch):
    gen, adapter = make_generator(monkeypatch, [
        lg.APIError("temporary failure"),
        response(confidence="high", input_type="args", args=["2"]),
    ])

    result = gen.generate(report())

    assert adapter.calls == 2
    assert result.args == ["2"]


def test_guardrail_fake_crash_rejected_and_retried(monkeypatch):
    gen, adapter = make_generator(monkeypatch, [
        response(confidence="high", input_type="args", args=["abort()"]),
        response(confidence="high", input_type="args", args=["safe_payload"]),
    ])

    result = gen.generate(report())

    assert adapter.calls == 2
    assert result.args == ["safe_payload"]
