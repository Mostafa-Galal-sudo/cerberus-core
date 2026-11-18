"""Shared LLM-agent scaffold: guardrails + structured tool-calling loop.

Both CERBERUS agents (DeepSeek attack, Groq defense) run on this scaffold so
guardrails live in exactly one place:

- **Scope locking** — `ScopePolicy` marks protected infrastructure (gateway,
  MQTT broker, SOC server, dashboard). Tool arguments that name a target are
  validated before anything executes; protected targets are untouchable,
  always.
- **Rate limiting** — `RateLimiter` caps each tool (min interval between calls
  + per-window budget) with an injectable clock for deterministic tests.
- **Structured function-calling only** — agents never execute free-form
  commands; every action is a registered `ToolSpec` handler.

The LLM client is any OpenAI-SDK-shaped object (`client.chat.completions.
create`), so tests inject scripted fakes and no real API calls happen.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Substrings that identify protected infrastructure. Case-insensitive match
# against any tool argument passed as `scope_arg`.
PROTECTED_TARGETS = ("gateway", "broker", "mosquitto", "soc", "dashboard")


class ScopeViolation(Exception):
    """A tool call targeted protected infrastructure."""


class RateLimitExceeded(Exception):
    """A tool call exceeded its rate budget."""


class AgentLoopError(Exception):
    """The tool-calling loop hit max_rounds without a final answer."""


class RateLimiter:
    """Token-bucket-lite: min interval between calls + max calls per window."""

    def __init__(
        self,
        min_interval: float = 0.0,
        max_per_window: int = 0,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.min_interval = min_interval
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self.clock = clock
        self._last = float("-inf")
        self._window: deque[float] = deque()

    def acquire(self) -> None:
        """Reserve one call slot or raise RateLimitExceeded."""
        now = self.clock()
        if self.min_interval and now - self._last < self.min_interval:
            raise RateLimitExceeded(
                f"min interval {self.min_interval}s between calls "
                f"(last call {now - self._last:.2f}s ago)"
            )
        if self.max_per_window:
            while self._window and now - self._window[0] >= self.window_seconds:
                self._window.popleft()
            if len(self._window) >= self.max_per_window:
                raise RateLimitExceeded(
                    f"max {self.max_per_window} calls per {self.window_seconds}s window"
                )
        self._window.append(now)
        self._last = now


class ScopePolicy:
    """Denies tool targets that match protected-infrastructure substrings."""

    def __init__(self, protected: tuple[str, ...] = PROTECTED_TARGETS):
        self.protected = tuple(p.lower() for p in protected)

    def check(self, target: object) -> None:
        text = str(target).lower()
        for token in self.protected:
            if token in text:
                raise ScopeViolation(
                    f"target '{target}' matches protected infrastructure '{token}'"
                )


@dataclass
class ToolSpec:
    """One callable tool exposed to the LLM via function-calling."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the arguments object
    handler: Callable[..., Any]
    scope_arg: str | None = None  # argument validated against ScopePolicy
    rate_limit: RateLimiter | None = None

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class AgentResult:
    """Outcome of one `LLMAgent.run()`."""

    content: str | None
    rounds: int
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)


class LLMAgent:
    """Tool-calling loop over any OpenAI-SDK-shaped chat-completions client."""

    def __init__(
        self,
        client: Any,
        model: str,
        system_prompt: str,
        tools: dict[str, ToolSpec],
        max_rounds: int = 8,
    ):
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.tools = tools
        self.max_rounds = max_rounds

    # -- guardrailed execution ---------------------------------------------
    def execute_tool(self, name: str, raw_arguments: str | dict) -> tuple[bool, str]:
        """Validate guardrails then run one tool. Never raises."""
        spec = self.tools.get(name)
        if spec is None:
            return False, f"ERROR: unknown tool '{name}'"
        if isinstance(raw_arguments, str):
            try:
                args = json.loads(raw_arguments) if raw_arguments.strip() else {}
            except json.JSONDecodeError as exc:
                return False, f"ERROR: invalid JSON arguments: {exc}"
        else:
            args = dict(raw_arguments)
        if not isinstance(args, dict):
            return False, "ERROR: arguments must be a JSON object"

        try:
            if spec.scope_arg is not None and spec.scope_arg in args:
                _scope_for(self).check(args[spec.scope_arg])
            if spec.rate_limit is not None:
                spec.rate_limit.acquire()
        except (ScopeViolation, RateLimitExceeded) as exc:
            logger.warning("Guardrail blocked %s: %s", name, exc)
            return False, f"ERROR: {type(exc).__name__}: {exc}"

        try:
            result = spec.handler(**args)
        except Exception as exc:
            logger.exception("Tool %s raised", name)
            return False, f"ERROR: {type(exc).__name__}: {exc}"
        if isinstance(result, str):
            return True, result
        return True, json.dumps(result, default=str)

    # -- main loop -----------------------------------------------------------
    def run(self, user_message: str, history: list[dict] | None = None) -> AgentResult:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            *(history or []),
            {"role": "user", "content": user_message},
        ]
        tools_payload = [spec.to_openai() for spec in self.tools.values()]
        trace: list[dict[str, Any]] = []

        for round_no in range(1, self.max_rounds + 1):
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools_payload,
            )
            message = response.choices[0].message
            calls = list(getattr(message, "tool_calls", None) or [])
            if not calls:
                return AgentResult(
                    content=message.content, rounds=round_no,
                    tool_trace=trace, messages=messages,
                )

            messages.append({
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.function.name,
                            "arguments": call.function.arguments,
                        },
                    }
                    for call in calls
                ],
            })
            for call in calls:
                ok, output = self.execute_tool(
                    call.function.name, call.function.arguments,
                )
                trace.append({
                    "tool": call.function.name,
                    "arguments": call.function.arguments,
                    "ok": ok,
                    "result": output,
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": output,
                })

        raise AgentLoopError(
            f"no final answer after {self.max_rounds} rounds "
            f"({len(trace)} tool calls)"
        )


def _scope_for(agent: LLMAgent) -> ScopePolicy:
    """Scope policy shared by every tool of an agent (created lazily)."""
    policy = getattr(agent, "_scope", None)
    if policy is None:
        policy = ScopePolicy()
        agent._scope = policy
    return policy
