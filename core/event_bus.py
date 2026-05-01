"""
Async publish/subscribe event bus.
All inter-agent communication flows through here — agents never call each other directly.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from enum import Enum
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class Topic(str, Enum):
    # Sentinel Mesh → Orchestrator
    THREAT_EVENT      = "threat.event"

    # Orchestrator → Triage
    INCIDENT_CREATED  = "incident.created"

    # Triage → Orchestrator / Red + Blue (parallel)
    TRIAGE_COMPLETE   = "triage.complete"

    # Red → Blue (Blue reads simulation before responding)
    SIMULATION_COMPLETE = "simulation.complete"

    # Blue → Orchestrator
    COUNTERMEASURES_READY = "countermeasures.ready"

    # Deception Weaver → Orchestrator (runs parallel to Blue)
    DECEPTION_DEPLOYED = "deception.deployed"

    # Orchestrator → Memory Crystallizer
    INCIDENT_RESOLVED = "incident.resolved"

    # Any agent → Dashboard
    AGENT_STATUS      = "agent.status"
    DASHBOARD_UPDATE  = "dashboard.update"


class AsyncEventBus:
    """
    A non-blocking, queue-backed pub/sub bus.

    Usage:
        bus.subscribe(Topic.TRIAGE_COMPLETE, my_async_handler)
        await bus.publish(Topic.TRIAGE_COMPLETE, payload)
    """

    def __init__(self) -> None:
        self._subscribers: Dict[Topic, List[Callable]] = defaultdict(list)
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running: bool = False

    # ── Subscription management ──────────────────────────────────────────────

    def subscribe(self, topic: Topic, callback: Callable) -> None:
        self._subscribers[topic].append(callback)
        logger.debug("Subscribed %s → %s", callback.__qualname__, topic)

    def unsubscribe(self, topic: Topic, callback: Callable) -> None:
        try:
            self._subscribers[topic].remove(callback)
        except ValueError:
            pass

    # ── Publishing ───────────────────────────────────────────────────────────

    async def publish(self, topic: Topic, data: Any) -> None:
        await self._queue.put((topic, data))

    def publish_sync(self, topic: Topic, data: Any) -> None:
        """Fire-and-forget from synchronous code (watchdog callbacks, etc.)."""
        try:
            loop = asyncio.get_event_loop()
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self.publish(topic, data))
            )
        except RuntimeError:
            pass

    # ── Event loop ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._running = True
        logger.info("Event bus started.")
        while self._running:
            try:
                topic, data = await asyncio.wait_for(
                    self._queue.get(), timeout=0.1
                )
                await self._dispatch(topic, data)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Event bus error: %s", exc)

    async def _dispatch(self, topic: Topic, data: Any) -> None:
        for callback in list(self._subscribers.get(topic, [])):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as exc:
                logger.exception(
                    "Handler %s failed on topic %s: %s",
                    callback.__qualname__, topic, exc
                )

    async def stop(self) -> None:
        self._running = False
        logger.info("Event bus stopped.")


# ── Singleton shared across all agents ──────────────────────────────────────
event_bus = AsyncEventBus()
