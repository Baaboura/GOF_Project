"""
Base Claude agent.
Every specialized agent inherits from this.  It handles:
  - Anthropic client initialisation
  - Calling Claude with optional tool use
  - Extracting structured JSON output via tool-forced responses
  - Broadcasting its status to the dashboard via the event bus
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI
from dotenv import load_dotenv

from core.event_bus import Topic, event_bus
from core.models import AgentRole, AgentStatus

load_dotenv()
logger = logging.getLogger(__name__)

# OpenRouter model — use any model available on openrouter.ai
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "anthropic/claude-sonnet-4-5")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")


class BaseAgent:
    """
    Abstract base for all mesh agents.

    Subclasses implement `run()` and declare their `role`.
    Uses OpenRouter (OpenAI-compatible API) to call Claude models.
    """

    role: AgentRole = AgentRole.ORCHESTRATOR

    def __init__(self, name: str, system_prompt: str) -> None:
        self.name = name
        self.system_prompt = system_prompt
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENROUTER_API_KEY not set. Copy .env.example → .env and fill it in."
            )
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=OPENROUTER_BASE_URL,
        )
        self.model = CLAUDE_MODEL

    # ── Claude call helpers ───────────────────────────────────────────────────

    async def _call_claude(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        max_tokens: int = 4096,
    ) -> Any:
        """Raw call via OpenRouter (OpenAI-compatible format)."""
        # Prepend system message
        full_messages = [{"role": "system", "content": self.system_prompt}] + messages

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": full_messages,
            "timeout": 120.0,
        }
        if tools:
            # Convert Anthropic tool format → OpenAI tool format
            openai_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", {}),
                    },
                }
                for t in tools
            ]
            kwargs["tools"] = openai_tools
        if tool_choice and isinstance(tool_choice, dict) and tool_choice.get("type") == "tool":
            # Force specific tool
            kwargs["tool_choice"] = {"type": "function", "function": {"name": tool_choice["name"]}}

        logger.info("[API] Calling %s via OpenRouter (%s)…", self.name, self.model)
        try:
            response = await self.client.chat.completions.create(**kwargs)
            logger.info("[API] %s got response OK", self.name)
            return response
        except Exception as exc:
            logger.error("[API] %s call FAILED: %s", self.name, exc)
            raise

    async def _structured_call(
        self,
        user_message: str,
        output_tool: Dict[str, Any],
        context: Optional[str] = None,
        max_tokens: int = 1000,
    ) -> Dict[str, Any]:
        """
        Force the model to return structured JSON by giving it a single tool
        and setting tool_choice to require it.

        The tool is never actually executed — it is purely a structured output
        schema that the model must fill in.
        """
        messages: List[Dict[str, Any]] = []
        if context:
            messages.append({"role": "user", "content": context})
            messages.append({"role": "assistant", "content": "Understood. I am ready to analyse."})
        messages.append({"role": "user", "content": user_message})

        response = await self._call_claude(
            messages=messages,
            tools=[output_tool],
            tool_choice={"type": "tool", "name": output_tool["name"]},
            max_tokens=max_tokens,
        )

        # Parse OpenAI-format tool call response
        choice = response.choices[0]
        if choice.message.tool_calls:
            tool_call = choice.message.tool_calls[0]
            if tool_call.function.name == output_tool["name"]:
                return json.loads(tool_call.function.arguments)

        raise ValueError(f"Agent {self.name} did not return expected tool call.")

    # ── Status broadcasts ─────────────────────────────────────────────────────

    async def _broadcast(self, status: str, message: str, incident_id: Optional[str] = None) -> None:
        await event_bus.publish(
            Topic.AGENT_STATUS,
            AgentStatus(
                agent=self.role,
                status=status,
                message=message,
                incident_id=incident_id,
            ),
        )

    async def _thinking(self, incident_id: Optional[str] = None) -> None:
        await self._broadcast("thinking", f"{self.name} is analysing…", incident_id)

    async def _complete(self, message: str, incident_id: Optional[str] = None) -> None:
        await self._broadcast("complete", message, incident_id)

    # ── Subclasses implement this ─────────────────────────────────────────────

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    @staticmethod
    def _to_list(value: Any) -> list:
        """
        Ensure a value is a list.
        Claude sometimes returns a JSON string or bullet string instead of a list.
        """
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            # Try JSON parse first
            stripped = value.strip()
            if stripped.startswith("["):
                try:
                    result = json.loads(stripped)
                    if isinstance(result, list):
                        return result
                except json.JSONDecodeError:
                    pass
            # Split bullet/newline list
            lines = [
                line.lstrip("-•* \t").strip()
                for line in stripped.splitlines()
                if line.strip() and line.strip() not in ("-", "•", "*")
            ]
            return [l for l in lines if l]
        return []
