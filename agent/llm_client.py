import json
import os
import time
from typing import Dict, List, Optional

import requests


class LLMClient:
    """
    Multi-provider LLM client.
    Supported providers: deepseek/openai/local (OpenAI-compatible), claude.
    """

    DEFAULT_MAX_RETRIES = 10
    DEFAULT_BASE_DELAY = 3
    DEFAULT_MAX_DELAY = 120

    def __init__(self, config: Dict):
        self.provider = config.get("provider", "deepseek")
        self.model = config.get("model", "deepseek-coder")
        self.api_key = self._resolve_api_key(config)
        self.api_base = config.get("api_base", "").rstrip("/")
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = config.get("max_tokens", 8192)
        self.timeout = config.get("timeout", 120)

        self.max_retries = config.get("max_retries", self.DEFAULT_MAX_RETRIES)
        self.base_delay = config.get("retry_base_delay", self.DEFAULT_BASE_DELAY)
        self.max_delay = config.get("retry_max_delay", self.DEFAULT_MAX_DELAY)
        fallback = config.get("fallback")
        self.fallback = LLMClient(fallback) if isinstance(fallback, dict) and fallback else None

    @staticmethod
    def _resolve_api_key(config: Dict) -> str:
        """
        Priority:
        1) llm.api_key_env -> read from environment variable
        2) llm.api_key as ${ENV_NAME}
        3) llm.api_key raw value
        """
        api_key_env = str(config.get("api_key_env", "") or "").strip()
        if api_key_env:
            return os.getenv(api_key_env, "").strip()

        api_key_raw = str(config.get("api_key", "") or "").strip()
        if api_key_raw.startswith("${") and api_key_raw.endswith("}") and len(api_key_raw) > 3:
            env_name = api_key_raw[2:-1].strip()
            if env_name:
                return os.getenv(env_name, "").strip()

        return api_key_raw

    def chat(self, messages: List[Dict], tools: Optional[List[Dict]] = None) -> Dict:
        try:
            if self.provider in ("deepseek", "openai", "local"):
                return self._chat_openai_compat(messages, tools)
            if self.provider == "claude":
                return self._chat_claude(messages, tools)
            raise ValueError(f"Unsupported provider: {self.provider}")
        except (RuntimeError, ValueError, requests.exceptions.RequestException) as error:
            if self.fallback is None:
                raise
            response = self.fallback.chat(messages, tools)
            response["fallback_used"] = True
            response["fallback_reason"] = str(error)
            response["fallback_model"] = self.fallback.model
            return response

    def tool_result_messages(self, tool_results: List[Dict]) -> List[Dict]:
        """Build provider-native tool result messages."""
        if self.provider == "claude":
            return [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": item["id"],
                            "content": item["content"],
                        }
                        for item in tool_results
                    ],
                }
            ]
        return [
            {
                "role": "tool",
                "tool_call_id": item["id"],
                "content": item["content"],
            }
            for item in tool_results
        ]

    @staticmethod
    def _extract_status_code(e: requests.exceptions.HTTPError) -> Optional[int]:
        if e.response is not None:
            return e.response.status_code
        import re

        m = re.search(r"\b(\d{3})\b", str(e))
        if m:
            return int(m.group(1))
        return None

    def _retry_post(self, url: str, headers: Dict, body: Dict):
        attempt = 0
        while True:
            try:
                resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)
                resp.raise_for_status()
                return resp
            except requests.exceptions.HTTPError as e:
                status_code = self._extract_status_code(e)
                if status_code in (429, 500, 502, 503, 504):
                    attempt += 1
                    if self.max_retries > 0 and attempt > self.max_retries:
                        raise RuntimeError(
                            f"LLM API failed after retries ({self.max_retries}), last HTTP {status_code}"
                        ) from e
                    delay = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
                    print(f"[LLMClient] HTTP {status_code}, retry {attempt}, wait {delay}s")
                    time.sleep(delay)
                else:
                    raise RuntimeError(f"LLM API request failed, HTTP {status_code}: {e}") from e
            except requests.exceptions.Timeout as e:
                attempt += 1
                if self.max_retries > 0 and attempt > self.max_retries:
                    raise RuntimeError(
                        f"LLM API timeout after retries ({self.max_retries})"
                    ) from e
                delay = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
                print(f"[LLMClient] Timeout, retry {attempt}, wait {delay}s")
                time.sleep(delay)
            except requests.exceptions.ConnectionError as e:
                attempt += 1
                if self.max_retries > 0 and attempt > self.max_retries:
                    raise RuntimeError(
                        f"LLM API connection failed after retries ({self.max_retries}): {e}"
                    ) from e
                delay = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
                print(f"[LLMClient] Connection error, retry {attempt}, wait {delay}s")
                time.sleep(delay)
            except Exception as e:
                attempt += 1
                if self.max_retries > 0 and attempt > self.max_retries:
                    raise RuntimeError(
                        f"LLM API error after retries ({self.max_retries}): {type(e).__name__}: {e}"
                    ) from e
                delay = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
                print(f"[LLMClient] Error {type(e).__name__}: {e}, retry {attempt}, wait {delay}s")
                time.sleep(delay)

    def _chat_openai_compat(self, messages: List[Dict], tools: Optional[List[Dict]]) -> Dict:
        url = f"{self.api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}

        if self.provider != "local":
            if not self.api_key:
                raise RuntimeError(
                    "LLM api_key is empty. Set llm.api_key_env in config and export that env variable."
                )
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: Dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            body["tools"] = [{"type": "function", "function": t} for t in tools]
            body["tool_choice"] = "auto"

        resp = self._retry_post(url, headers, body)
        data = resp.json()

        choice = data["choices"][0]["message"]
        content = choice.get("content") or ""
        tool_calls_raw = choice.get("tool_calls") or []
        tokens_used = data.get("usage", {}).get("total_tokens", 0)

        tool_calls = []
        for tc in tool_calls_raw:
            args_str = tc.get("function", {}).get("arguments", "{}")
            try:
                args = json.loads(args_str)
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(
                {
                    "name": tc.get("function", {}).get("name", ""),
                    "args": args,
                    "id": tc.get("id", ""),
                }
            )

        return {
            "content": content,
            "tool_calls": tool_calls,
            "assistant_message": {
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls_raw,
            },
            "tokens_used": tokens_used,
        }

    def _chat_claude(self, messages: List[Dict], tools: Optional[List[Dict]]) -> Dict:
        if not self.api_key:
            raise RuntimeError(
                "LLM api_key is empty. Set llm.api_key_env in config and export that env variable."
            )

        url = f"{self.api_base}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        system = ""
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                user_messages.append(m)

        body: Dict = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": user_messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "input_schema": t.get("parameters", {}),
                }
                for t in tools
            ]

        resp = self._retry_post(url, headers, body)
        data = resp.json()

        content = ""
        tool_calls = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    {
                        "name": block.get("name", ""),
                        "args": block.get("input", {}),
                        "id": block.get("id", ""),
                    }
                )

        usage = data.get("usage", {})
        tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        return {
            "content": content,
            "tool_calls": tool_calls,
            "assistant_message": {
                "role": "assistant",
                "content": data.get("content", []),
            },
            "tokens_used": tokens_used,
        }
