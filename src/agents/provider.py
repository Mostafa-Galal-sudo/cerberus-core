"""Generic LLM provider adapter for C3-Extended / E3.

Design constraints:
- API keys are read from the environment (or an injected secret store) only;
  they are never logged or written to disk by this module.
- Every provider call goes through one bounded path: timeout -> retry ->
  circuit breaker -> call/cost budget -> normalized response.
- The deterministic fallback in ``fallback.py`` remains authoritative when
  this module raises. No provider output is trusted as a policy decision.

Legacy Groq (defense) and DeepSeek (attack) paths are preserved as provider
profiles, so existing deployments keep working without configuration changes.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

ROLES = ("defense", "attack")


class ProviderError(RuntimeError):
    """Base class for adapter errors that must trigger deterministic fallback."""


class ProviderUnavailable(ProviderError):
    """No key, circuit open, or budget exhausted; no request was attempted."""


class ProviderRequestError(ProviderError):
    """The provider request failed after the configured attempts."""


def redact_secrets(text: Any, env: dict[str, str] | None = None) -> str:
    """Strip configured key values from any text that may reach a log or incident."""
    env = env if env is not None else os.environ
    out = str(text)
    for profile in PROFILES.values():
        for name in profile.key_env:
            value = str(env.get(name, "") or "").strip()
            if value:
                out = out.replace(value, "[REDACTED]")
    return out


def _clean(value: str | None) -> str:
    return (value or "").strip().lower()


def _env_int(env: dict[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = str(env.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _env_float(env: dict[str, str], name: str, default: float, minimum: float = 0.0) -> float:
    raw = str(env.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


@dataclass(frozen=True)
class ProviderProfile:
    """Static capability description for one LLM provider."""

    name: str
    label: str
    key_env: tuple[str, ...]
    sdk: str  # "openai" | "groq" | "anthropic"
    base_url: str | None = None
    default_model: str = ""
    model_env: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    requires_key: bool = True
    placeholder_key: str | None = None

    def api_key(self, env: dict[str, str]) -> str | None:
        for name in self.key_env:
            value = str(env.get(name, "") or "").strip()
            if value:
                return value
        # Local providers such as Ollama need a non-secret SDK placeholder only.
        return self.placeholder_key if not self.requires_key else None

    def model(self, env: dict[str, str]) -> str:
        if self.model_env:
            value = str(env.get(self.model_env, "") or "").strip()
            if value:
                return value
        return self.default_model


# Placeholder defaults are overridable with CERBERUS_<PROVIDER>_MODEL. Live model
# IDs are only claimed after a keyed verification run, which has not happened yet.
PROFILES: dict[str, ProviderProfile] = {
    "openai": ProviderProfile(
        "openai", "OpenAI", ("OPENAI_API_KEY",), "openai",
        default_model="gpt-4o-mini", model_env="CERBERUS_OPENAI_MODEL",
    ),
    "anthropic": ProviderProfile(
        "anthropic", "Anthropic", ("ANTHROPIC_API_KEY",), "anthropic",
        default_model="claude-3-5-haiku-latest", model_env="CERBERUS_ANTHROPIC_MODEL",
    ),
    "google": ProviderProfile(
        "google", "Google AI Studio", ("GOOGLE_API_KEY", "GEMINI_API_KEY"), "openai",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        default_model="gemini-2.0-flash", model_env="CERBERUS_GOOGLE_MODEL",
    ),
    "openrouter": ProviderProfile(
        "openrouter", "OpenRouter", ("OPENROUTER_API_KEY",), "openai",
        base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-4o-mini", model_env="CERBERUS_OPENROUTER_MODEL",
        headers={"HTTP-Referer": "https://cerberus.local", "X-Title": "Cerberus SOC"},
    ),
    "ollama": ProviderProfile(
        "ollama", "Ollama (local)", ("OLLAMA_API_KEY",), "openai",
        base_url="http://127.0.0.1:11434/v1",
        default_model="qwen3-vl:4b-instruct", model_env="CERBERUS_OLLAMA_MODEL",
        requires_key=False, placeholder_key="ollama",
    ),
    "groq": ProviderProfile(
        "groq", "Groq (legacy)", ("GROQ_API_KEY",), "groq",
        default_model="llama-3.3-70b-versatile", model_env="CERBERUS_GROQ_MODEL",
    ),
    "deepseek": ProviderProfile(
        "deepseek", "DeepSeek (legacy)", ("DEEPSEEK_API_KEY",), "openai",
        base_url="https://api.deepseek.com",
        default_model="deepseek-chat", model_env="CERBERUS_DEEPSEEK_MODEL",
    ),
}

PRIORITY = ("openai", "anthropic", "google", "openrouter")
LEGACY = {"defense": "groq", "attack": "deepseek"}


def _ab_providers(role: str, env: dict[str, str]) -> list[str]:
    raw = str(
        env.get(f"CERBERUS_{role.upper()}_AB_PROVIDERS")
        or env.get("CERBERUS_LLM_AB_PROVIDERS")
        or ""
    )
    seen: list[str] = []
    for part in raw.split(","):
        name = _clean(part)
        if name in PROFILES and name not in seen:
            seen.append(name)
    return seen


def resolve_provider(role: str, *, env: dict[str, str] | None = None, assignment_key: str | None = None) -> str:
    """Pick a provider for *role* without creating a client or making a request.

    A/B: when at least two configured providers are named in
    ``CERBERUS_<ROLE>_AB_PROVIDERS`` / ``CERBERUS_LLM_AB_PROVIDERS``, the choice
    is a stable hash of ``role:assignment_key`` so one incident/attack always
    uses the same provider. This is the experiment assignment mechanism; the
    comparison itself requires real keys and is not claimed without them.
    """
    env = env if env is not None else os.environ
    role = role if role in ROLES else "defense"
    ab = [name for name in _ab_providers(role, env) if PROFILES[name].api_key(env)]
    if ab:
        if len(ab) == 1:
            return ab[0]
        seed = f"{role}:{assignment_key or ''}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        return ab[int(digest, 16) % len(ab)]

    explicit = _clean(env.get(f"CERBERUS_{role.upper()}_PROVIDER"))
    if explicit:
        return explicit
    legacy = LEGACY[role]
    if PROFILES[legacy].api_key(env):
        return legacy
    for name in PRIORITY:
        if PROFILES[name].api_key(env):
            return name
    return legacy


def build_health_status(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Non-network health snapshot for the dashboard and tests."""
    env = env if env is not None else os.environ
    out: dict[str, Any] = {"roles": {}, "ab": {}}
    for role in ROLES:
        name = resolve_provider(role, env=env)
        profile = PROFILES.get(name)
        key_present = bool(profile and profile.api_key(env))
        ab = [p for p in _ab_providers(role, env) if PROFILES[p].api_key(env)]
        out["roles"][role] = {
            "provider": name,
            "label": profile.label if profile else name,
            "model": profile.model(env) if profile else None,
            "mode": "live" if key_present else "fallback",
            "ab_providers": ab if len(ab) >= 2 else [],
        }
    out["ab"]["enabled"] = any(bool(v["ab_providers"]) for v in out["roles"].values())
    return out


@dataclass
class ProviderStatus:
    configured: bool
    provider: str
    model: str | None
    mode: str  # "live" | "fallback"
    circuit: str  # "closed" | "open" | "half-open"
    calls: int
    max_calls: int
    remaining_calls: int
    estimated_usd: float
    max_estimated_usd: float
    last_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "provider": self.provider,
            "model": self.model,
            "mode": self.mode,
            "circuit": self.circuit,
            "calls": self.calls,
            "max_calls": self.max_calls,
            "remaining_calls": self.remaining_calls,
            "estimated_usd": round(self.estimated_usd, 6),
            "max_estimated_usd": self.max_estimated_usd,
            "last_error": self.last_error,
        }


@dataclass
class CompletionResult:
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    provider: str = ""
    model: str | None = None
    usage: dict[str, Any] | None = None


def _attr(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _usage_dict(usage: Any) -> dict[str, Any] | None:
    if usage is None:
        return None
    if isinstance(usage, dict):
        return dict(usage)
    keys = (
        "total_tokens", "prompt_tokens", "completion_tokens",
        "input_tokens", "output_tokens", "cached_tokens",
    )
    return {key: getattr(usage, key) for key in keys if hasattr(usage, key)} or None


def _usage_total(usage: dict[str, Any] | None) -> int:
    if not usage:
        return 0
    total = usage.get("total_tokens")
    if isinstance(total, (int, float)):
        return int(total)
    prompt = usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0
    completion = usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0
    try:
        return int(prompt) + int(completion)
    except (TypeError, ValueError):
        return 0


def _normalise_openai_like(response: Any) -> CompletionResult:
    choices = _attr(response, "choices", []) or []
    if not choices:
        raise ProviderRequestError("provider returned no choices")
    message = _attr(choices[0], "message") or {}
    content = _attr(message, "content", "") or ""
    tool_calls: list[dict[str, Any]] = []
    for call in _attr(message, "tool_calls", None) or []:
        function = _attr(call, "function", None) or {}
        tool_calls.append(
            {
                "id": _attr(call, "id", "") or "",
                "type": "function",
                "function": {
                    "name": _attr(function, "name", "") or "",
                    "arguments": _attr(function, "arguments", "{}") or "{}",
                },
            }
        )
    return CompletionResult(content=str(content), tool_calls=tool_calls, usage=_usage_dict(_attr(response, "usage")))


def _normalise_anthropic(response: Any) -> CompletionResult:
    blocks = _attr(response, "content", []) or []
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in blocks:
        kind = _attr(block, "type", "")
        if kind == "text":
            text_parts.append(str(_attr(block, "text", "") or ""))
        elif kind == "tool_use":
            tool_calls.append(
                {
                    "id": _attr(block, "id", "") or "",
                    "type": "function",
                    "function": {
                        "name": _attr(block, "name", "") or "",
                        "arguments": json.dumps(_attr(block, "input", {}) or {}),
                    },
                }
            )
    return CompletionResult(content="".join(text_parts), tool_calls=tool_calls, usage=_usage_dict(_attr(response, "usage")))


class ProviderAdapter:
    """One bounded request path shared by the defense and attack agents."""

    def __init__(
        self,
        role: str = "defense",
        *,
        env: dict[str, str] | None = None,
        client: Any = None,
        provider: str | None = None,
        model: str | None = None,
        assignment_key: str | None = None,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._env = env if env is not None else os.environ
        self.role = role if role in ROLES else "defense"
        self._injected = client is not None
        self._client = client
        self.provider = _clean(provider) if provider else resolve_provider(
            self.role, env=self._env, assignment_key=assignment_key
        )
        self._explicit_model = model
        self._sleep = sleep or time.sleep
        self._clock = clock or time.monotonic

        self.max_attempts = _env_int(self._env, "CERBERUS_LLM_MAX_ATTEMPTS", 2)
        self.retry_base = _env_float(self._env, "CERBERUS_LLM_RETRY_BASE_S", 0.25)
        self.retry_max = _env_float(self._env, "CERBERUS_LLM_RETRY_MAX_S", 2.0)
        self.timeout = _env_float(self._env, "CERBERUS_LLM_TIMEOUT_S", 20.0, minimum=1.0)
        self.max_calls = _env_int(self._env, "CERBERUS_LLM_MAX_CALLS", 100)
        self.max_estimated_usd = _env_float(self._env, "CERBERUS_LLM_MAX_ESTIMATED_USD", 1.0)
        self.usd_per_1k = _env_float(self._env, "CERBERUS_LLM_USD_PER_1K_TOKENS", 0.0)
        self.max_tokens = _env_int(self._env, "CERBERUS_LLM_MAX_TOKENS", 1024)
        self.circuit_failures = _env_int(self._env, "CERBERUS_LLM_CIRCUIT_FAILURES", 3)
        self.cooldown = _env_float(self._env, "CERBERUS_LLM_CIRCUIT_COOLDOWN_S", 30.0)

        self.calls = 0
        self.estimated_usd = 0.0
        self.consecutive_failures = 0
        self.opened_at: float | None = None
        self.half_open = False
        self.last_error: str | None = None

    # -- configuration / state ------------------------------------------------
    def _profile(self) -> ProviderProfile | None:
        return PROFILES.get(self.provider)

    def _model(self, explicit: str | None) -> str:
        if explicit or self._explicit_model:
            return explicit or self._explicit_model or "unknown"
        profile = self._profile()
        if profile:
            return profile.model(self._env)
        return "unknown"

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        profile = self._profile()
        api_key = profile.api_key(self._env) if profile else None
        if not profile or not api_key:
            raise ProviderUnavailable(f"no API key configured for provider {self.provider!r}")
        try:
            if profile.sdk == "groq":
                from groq import Groq

                self._client = Groq(api_key=api_key)
            elif profile.sdk == "anthropic":
                from anthropic import Anthropic

                self._client = Anthropic(api_key=api_key)
            else:
                from openai import OpenAI

                kwargs: dict[str, Any] = {"api_key": api_key}
                if profile.base_url:
                    kwargs["base_url"] = profile.base_url
                if profile.headers:
                    kwargs["default_headers"] = dict(profile.headers)
                self._client = OpenAI(**kwargs)
        except Exception as exc:
            raise ProviderUnavailable(f"cannot initialise {self.provider} client: {exc}") from exc
        return self._client

    def _circuit_state(self) -> str:
        if self.opened_at is None:
            return "closed"
        if self._clock() - self.opened_at >= self.cooldown:
            return "half-open"
        return "open"

    def _check_circuit(self) -> None:
        if self.opened_at is None:
            return
        if self._circuit_state() == "open":
            raise ProviderUnavailable(f"circuit open for {self.provider}")
        if not self.half_open:
            self.half_open = True
            return
        raise ProviderUnavailable(f"circuit half-open; probe in flight for {self.provider}")

    def _check_budget(self) -> None:
        if self.calls >= self.max_calls:
            raise ProviderUnavailable(f"call budget exhausted for {self.provider}")
        if self.max_estimated_usd > 0 and self.estimated_usd >= self.max_estimated_usd:
            raise ProviderUnavailable("estimated spend cap reached")

    def _on_success(self, usage: dict[str, Any] | None) -> None:
        self.consecutive_failures = 0
        self.opened_at = None
        self.half_open = False
        self.last_error = None
        if self.usd_per_1k > 0:
            self.estimated_usd += (_usage_total(usage) / 1000.0) * self.usd_per_1k

    def _on_failure(self, exc: Exception) -> None:
        self.last_error = redact_secrets(f"{type(exc).__name__}: {exc}", self._env)[:400]
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.circuit_failures and self.opened_at is None:
            self.opened_at = self._clock()
            self.half_open = False

    def status(self) -> ProviderStatus:
        profile = self._profile()
        key_present = bool(profile and profile.api_key(self._env))
        configured = self._injected or key_present
        remaining = max(0, self.max_calls - self.calls)
        return ProviderStatus(
            configured=configured,
            provider=self.provider,
            model=self._model(None),
            mode="live" if configured else "fallback",
            circuit=self._circuit_state(),
            calls=self.calls,
            max_calls=self.max_calls,
            remaining_calls=remaining,
            estimated_usd=self.estimated_usd,
            max_estimated_usd=self.max_estimated_usd,
            last_error=self.last_error,
        )

    # -- request construction -------------------------------------------------
    def _request_kwargs(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        tool_choice: str,
        temperature: float,
    ) -> dict[str, Any]:
        profile = self._profile()
        sdk = profile.sdk if profile else "openai"
        if sdk == "anthropic":
            system_parts: list[str] = []
            chat: list[dict[str, Any]] = []
            for message in messages:
                role = message.get("role", "user")
                if role == "system":
                    system_parts.append(str(message.get("content", "") or ""))
                elif role == "tool":
                    chat.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": message.get("tool_call_id", ""),
                                    "content": str(message.get("content", "") or ""),
                                }
                            ],
                        }
                    )
                else:
                    chat.append({"role": role, "content": message.get("content", "") or ""})
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": chat,
                "max_tokens": self.max_tokens,
                "temperature": temperature,
                "timeout": self.timeout,
            }
            if system_parts:
                kwargs["system"] = "\n".join(system_parts)
            if tools:
                kwargs["tools"] = [
                    {
                        "name": tool["function"]["name"],
                        "description": tool["function"].get("description", ""),
                        "input_schema": tool["function"].get("parameters", {"type": "object", "properties": {}}),
                    }
                    for tool in tools
                ]
            return kwargs

        kwargs = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "timeout": self.timeout,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        return kwargs

    # -- public call ----------------------------------------------------------
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        temperature: float = 0.1,
    ) -> CompletionResult:
        chosen_model = self._model(model)
        profile = self._profile()
        sdk = profile.sdk if profile else "openai"
        last_exc: Exception | None = None

        for attempt in range(self.max_attempts):
            self._check_budget()
            self._check_circuit()
            client = self._get_client()
            kwargs = self._request_kwargs(chosen_model, messages, tools, tool_choice, temperature)
            self.calls += 1
            try:
                if sdk == "anthropic":
                    result = _normalise_anthropic(client.messages.create(**kwargs))
                else:
                    result = _normalise_openai_like(client.chat.completions.create(**kwargs))
            except ProviderError:
                raise
            except Exception as exc:
                last_exc = exc
                self._on_failure(exc)
                if attempt + 1 < self.max_attempts:
                    self._sleep(min(self.retry_base * (2**attempt), self.retry_max))
                    continue
                break
            else:
                self._on_success(result.usage)
                result.provider = self.provider
                result.model = chosen_model
                return result

        raise ProviderRequestError(
            redact_secrets(
                f"{self.provider} request failed after {self.max_attempts} attempt(s): {last_exc}",
                self._env,
            )
        ) from last_exc
