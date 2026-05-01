"""
Adversarial Cognitive Mesh — Entry Point
==========================================
Usage:
    python cyber_main.py --demo                        # Random attack scenario
    python cyber_main.py --demo --scenario ransomware  # Specific scenario
    python cyber_main.py --demo --scenario apt_intrusion
    python cyber_main.py --demo --scenario cryptominer
    python cyber_main.py --monitor                     # Real system monitoring

Prerequisites:
    pip install -r requirements.txt
    cp .env.example .env
    # Set ANTHROPIC_API_KEY in .env
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from typing import Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

load_dotenv()

console = Console()

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "WARNING")),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """
  ╔═══════════════════════════════════════════════════════════╗
  ║        ADVERSARIAL COGNITIVE MESH  v1.0                  ║
  ║                                                           ║
  ║   Layer 1  Sentinel Mesh     — Multi-surface sensors      ║
  ║   Layer 2  Cognitive Triage  — MITRE ATT&CK narrative     ║
  ║   Layer 3  Red Agent         — Adversarial simulation     ║
  ║   Layer 4  Blue Agent        — Pre-emptive countermeasures║
  ║   Layer 5  Deception Weaver  — Tailored honeypots         ║
  ║   Layer 6  Memory Crystallizer — Threat DNA learning      ║
  ╚═══════════════════════════════════════════════════════════╝
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))


# ── Core async runner ─────────────────────────────────────────────────────────

async def run_mesh(
    demo: bool = True,
    scenario: Optional[str] = None,
    timeout: float = 300.0,
) -> None:
    from agents.sentinel_mesh import SentinelMesh, DEMO_SCENARIOS
    from core.event_bus import Topic, event_bus
    from core.orchestrator import Orchestrator
    from dashboard.terminal import TerminalDashboard

    # Validate scenario
    if scenario and scenario not in DEMO_SCENARIOS:
        console.print(
            f"[red]Unknown scenario '{scenario}'. "
            f"Available: {', '.join(DEMO_SCENARIOS.keys())}[/]"
        )
        return

    # Instantiate components
    orchestrator = Orchestrator()
    sentinel = SentinelMesh(demo_mode=demo, scenario=scenario)
    dashboard = TerminalDashboard()

    orchestrator.set_scenario(sentinel.scenario_name)

    # Wire final report callback
    final_report = {}
    def on_report(report):
        final_report["report"] = report

    orchestrator.on_report_complete = on_report

    # Subscribe orchestrator to sentinel events
    event_bus.subscribe(Topic.THREAT_EVENT, orchestrator.on_threat_event)

    # Subscribe dashboard to all status topics
    async def on_agent_status(status):
        dashboard.update_agent_status(status)
        dashboard.refresh()

    async def on_dashboard_update(payload):
        dashboard.update_from_bus(payload)
        dashboard.refresh()

    event_bus.subscribe(Topic.AGENT_STATUS, on_agent_status)
    event_bus.subscribe(Topic.DASHBOARD_UPDATE, on_dashboard_update)

    # Print banner and scenario info
    print_banner()
    console.print(
        Panel(
            f"[bold]Mode:[/] {'DEMO' if demo else 'REAL MONITOR'}\n"
            f"[bold]Scenario:[/] [yellow]{sentinel.scenario_name}[/]\n"
            f"[bold]Model:[/] {os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-6')}\n\n"
            f"[dim]The mesh will run through all 6 layers automatically.\n"
            f"Press Ctrl+C to stop early.[/]",
            title="[cyan]Starting Adversarial Cognitive Mesh[/]",
            border_style="cyan",
        )
    )

    await asyncio.sleep(1)

    # Start live dashboard and run everything
    with dashboard.start_live() as live:
        # Start event bus in background
        bus_task = asyncio.create_task(event_bus.start())

        # Start sentinel
        await sentinel.start()

        # Wait for resolution or timeout
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            await asyncio.sleep(0.5)
            dashboard.refresh()
            if "report" in final_report:
                # Give dashboard a moment to show resolved state
                await asyncio.sleep(3)
                break

        bus_task.cancel()
        try:
            await bus_task
        except asyncio.CancelledError:
            pass

    # Print final report outside the live context (avoids rendering conflict)
    if "report" in final_report:
        dashboard.print_final_report(final_report["report"])
    else:
        console.print("[yellow]No incident was resolved within the timeout.[/]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Adversarial Cognitive Mesh — Multi-Agent Cybersecurity System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cyber_main.py --demo
  python cyber_main.py --demo --scenario ransomware
  python cyber_main.py --demo --scenario apt_intrusion
  python cyber_main.py --demo --scenario cryptominer
  python cyber_main.py --monitor --timeout 300
        """,
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo",    action="store_true", help="Run a scripted demo scenario")
    mode.add_argument("--monitor", action="store_true", help="Real system monitoring (psutil + watchdog)")

    p.add_argument(
        "--scenario",
        choices=["ransomware", "apt_intrusion", "cryptominer"],
        default=None,
        help="Demo scenario to run (default: random)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Maximum seconds to wait for incident resolution (default: 180)",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override LOG_LEVEL from .env",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(args.log_level)

    # Check API key
    if not os.getenv("OPENROUTER_API_KEY"):
        console.print(
            "[bold red]ERROR: OPENROUTER_API_KEY not set.[/]\n"
            "Copy [cyan].env.example[/] → [cyan].env[/] and add your key."
        )
        sys.exit(1)

    try:
        asyncio.run(
            run_mesh(
                demo=args.demo,
                scenario=args.scenario,
                timeout=args.timeout,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")


if __name__ == "__main__":
    main()
