"""
Rich terminal dashboard — real-time view of the mesh as it runs.

Layout:
┌─────────────────────────────────────────────────┐
│  ADVERSARIAL COGNITIVE MESH — Live Dashboard     │
├──────────────┬──────────────────────────────────┤
│ Agent Status │ Incident Feed                    │
├──────────────┴──────────────────────────────────┤
│ Threat Timeline (events + agent actions)        │
└─────────────────────────────────────────────────┘
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.style import Style
from rich.table import Table
from rich.text import Text

from core.models import (
    AgentRole, AgentStatus, BlueAgentResponse, DeceptionPlan,
    IncidentReport, IncidentStatus, SeverityLevel,
    ThreatEvent, ThreatIncident, ThreatNarrative, AttackSimulation,
)

# ── Colour palette ────────────────────────────────────────────────────────────

SEVERITY_STYLE: Dict[SeverityLevel, str] = {
    SeverityLevel.LOW:      "green",
    SeverityLevel.MEDIUM:   "yellow",
    SeverityLevel.HIGH:     "bold red",
    SeverityLevel.CRITICAL: "bold white on red",
}

AGENT_STYLE: Dict[AgentRole, str] = {
    AgentRole.SENTINEL:    "cyan",
    AgentRole.TRIAGE:      "yellow",
    AgentRole.RED:         "bold red",
    AgentRole.BLUE:        "bold blue",
    AgentRole.DECEPTION:   "magenta",
    AgentRole.MEMORY:      "green",
    AgentRole.ORCHESTRATOR: "white",
}

AGENT_ICON: Dict[AgentRole, str] = {
    AgentRole.SENTINEL:    "👁",
    AgentRole.TRIAGE:      "🧠",
    AgentRole.RED:         "💀",
    AgentRole.BLUE:        "🛡",
    AgentRole.DECEPTION:   "🎭",
    AgentRole.MEMORY:      "🧬",
    AgentRole.ORCHESTRATOR: "⚙",
}

STATUS_ICON = {
    "idle":     "○",
    "thinking": "◉",
    "complete": "✓",
    "error":    "✗",
}


class TerminalDashboard:
    """
    Renders a live Rich dashboard.
    Feed it events via `update()`.
    """

    MAX_TIMELINE = 40

    def __init__(self) -> None:
        self.console = Console()
        self._live: Optional[Live] = None

        # State
        self._agent_statuses: Dict[AgentRole, AgentStatus] = {}
        self._events: Deque[ThreatEvent] = deque(maxlen=self.MAX_TIMELINE)
        self._timeline: Deque[str] = deque(maxlen=self.MAX_TIMELINE)
        self._incidents: Dict[str, ThreatIncident] = {}
        self._reports: Dict[str, IncidentReport] = {}
        self._active_narrative: Optional[ThreatNarrative] = None
        self._active_simulation: Optional[AttackSimulation] = None
        self._active_blue: Optional[BlueAgentResponse] = None
        self._active_deception: Optional[DeceptionPlan] = None
        self._memory_count: int = 0
        self._start_time: float = time.monotonic()

    # ── Update handlers ───────────────────────────────────────────────────────

    def update_agent_status(self, status: AgentStatus) -> None:
        self._agent_statuses[status.agent] = status
        icon = STATUS_ICON.get(status.status, "?")
        self._timeline.append(
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
            f"[{AGENT_STYLE.get(status.agent, 'white')}]{AGENT_ICON.get(status.agent, '')} "
            f"{status.agent.value.upper()}[/] {icon} {status.message[:70]}"
        )

    def update_from_bus(self, payload: Dict[str, Any]) -> None:
        ptype = payload.get("type", "")

        if ptype == "new_event":
            event: ThreatEvent = payload["event"]
            self._events.append(event)
            conf_bar = "█" * int(event.confidence * 10) + "░" * (10 - int(event.confidence * 10))
            self._timeline.append(
                f"[dim]{event.timestamp.strftime('%H:%M:%S')}[/] "
                f"[cyan]SENSOR[/] [{event.sensor_type.upper()}] "
                f"[yellow]{conf_bar}[/] {event.description[:65]}"
            )

        elif ptype == "incident_created":
            inc: ThreatIncident = payload["incident"]
            self._incidents[inc.id] = inc
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[bold yellow]INCIDENT OPENED[/] #{inc.id} — "
                f"{len(inc.events)} events escalated"
            )

        elif ptype == "triage_complete":
            self._active_narrative = payload["narrative"]
            n = self._active_narrative
            sev_style = SEVERITY_STYLE.get(n.severity, "white")
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[yellow]TRIAGE[/] Stage: {n.kill_chain_stage} | "
                f"[{sev_style}]{n.severity.upper()}[/] | "
                f"{len(n.mitre_techniques)} techniques | Confidence {n.confidence:.0%}"
            )

        elif ptype == "simulation_complete":
            self._active_simulation = payload["simulation"]
            self._active_deception = payload["deception"]
            s = self._active_simulation
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[red]RED AGENT[/] {len(s.kill_chain)}-step kill chain simulated | "
                f"ETA: {s.time_to_completion}"
            )
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[magenta]DECEPTION[/] {len(self._active_deception.assets)} assets designed | "
                f"{self._active_deception.time_window}"
            )

        elif ptype == "countermeasures_ready":
            self._active_blue = payload["response"]
            b = self._active_blue
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[blue]BLUE AGENT[/] {len(b.countermeasures)} countermeasures | "
                f"{b.overall_strategy[:60]}"
            )

        elif ptype == "memory_hit":
            similar = payload.get("similar", [])
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[green]MEMORY HIT[/] Similar past threats: {', '.join(similar[:3])}"
            )

        elif ptype == "incident_resolved":
            report: IncidentReport = payload["report"]
            self._reports[report.incident.id] = report
            if report.threat_dna:
                self._memory_count += 1
            self._timeline.append(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                f"[bold green]RESOLVED[/] #{report.incident.id} in "
                f"{report.duration_seconds:.1f}s | "
                f"DNA: {report.threat_dna.fingerprint_hash if report.threat_dna else 'none'}"
            )

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _render_header(self) -> Panel:
        elapsed = time.monotonic() - self._start_time
        minutes, seconds = divmod(int(elapsed), 60)
        header = Table.grid(expand=True)
        header.add_column(justify="left")
        header.add_column(justify="center")
        header.add_column(justify="right")
        header.add_row(
            Text("ADVERSARIAL COGNITIVE MESH", style="bold cyan"),
            Text("◈ LIVE MONITORING ◈", style="bold white"),
            Text(f"Uptime {minutes:02d}:{seconds:02d} | "
                 f"Events: {len(self._events)} | "
                 f"Incidents: {len(self._incidents)} | "
                 f"DNA: {self._memory_count}", style="dim"),
        )
        return Panel(header, style="cyan", box=box.DOUBLE_EDGE)

    def _render_agents(self) -> Panel:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold white", expand=True)
        table.add_column("Agent", style="bold", width=14)
        table.add_column("Status", width=10)
        table.add_column("Last Message")

        all_roles = [
            AgentRole.SENTINEL, AgentRole.TRIAGE, AgentRole.RED,
            AgentRole.BLUE, AgentRole.DECEPTION, AgentRole.MEMORY,
        ]
        for role in all_roles:
            st = self._agent_statuses.get(role)
            icon = AGENT_ICON.get(role, "")
            style = AGENT_STYLE.get(role, "white")
            status_icon = STATUS_ICON.get(st.status if st else "idle", "○")
            status_text = st.status if st else "idle"
            msg = st.message[:55] if st else "—"
            table.add_row(
                f"[{style}]{icon} {role.value}[/]",
                f"{status_icon} {status_text}",
                f"[dim]{msg}[/]",
            )
        return Panel(table, title="[bold]Agent Layer[/]", border_style="white")

    def _render_narrative(self) -> Panel:
        if not self._active_narrative:
            return Panel(
                Align.center(Text("Waiting for triage…", style="dim italic"), vertical="middle"),
                title="[bold yellow]Threat Narrative[/]",
                border_style="yellow",
                height=12,
            )

        n = self._active_narrative
        sev_style = SEVERITY_STYLE.get(n.severity, "white")

        content = Table.grid(padding=(0, 1))
        content.add_column(style="bold dim", width=18)
        content.add_column()
        content.add_row("Stage:", n.kill_chain_stage)
        content.add_row("Severity:", f"[{sev_style}]{n.severity.upper()}[/]")
        content.add_row("Tactic:", n.current_tactic)
        content.add_row("Intent:", n.attacker_intent[:70])
        content.add_row(
            "Techniques:",
            ", ".join(f"[yellow]{t.id}[/]" for t in n.mitre_techniques[:6]),
        )
        content.add_row("Next moves:", n.predicted_next_steps[0][:65] if n.predicted_next_steps else "—")
        content.add_row("Confidence:", f"{n.confidence:.0%}")

        return Panel(content, title="[bold yellow]Threat Narrative[/]", border_style="yellow")

    def _render_simulation(self) -> Panel:
        if not self._active_simulation:
            return Panel(
                Align.center(Text("Waiting for Red Agent…", style="dim italic"), vertical="middle"),
                title="[bold red]Red Agent — Kill Chain[/]",
                border_style="red",
                height=10,
            )

        s = self._active_simulation
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold red", expand=True)
        table.add_column("#", width=3, style="dim")
        table.add_column("Tech", width=8, style="red")
        table.add_column("Target", width=20)
        table.add_column("Description")
        table.add_column("ETA", width=8, style="dim")

        for i, step in enumerate(s.kill_chain[:6]):
            table.add_row(
                str(i + 1),
                step.technique_id,
                step.target[:18],
                step.description[:40],
                step.time_offset,
            )

        return Panel(table, title=f"[bold red]Red Agent — {len(s.kill_chain)}-step Kill Chain[/]", border_style="red")

    def _render_blue(self) -> Panel:
        if not self._active_blue:
            return Panel(
                Align.center(Text("Waiting for Blue Agent…", style="dim italic"), vertical="middle"),
                title="[bold blue]Blue Agent — Countermeasures[/]",
                border_style="blue",
                height=10,
            )

        b = self._active_blue
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold blue", expand=True)
        table.add_column("P", width=3, style="bold")
        table.add_column("Action", width=18, style="blue")
        table.add_column("Target", width=18)
        table.add_column("Description")
        table.add_column("Rev", width=4)

        for cm in b.countermeasures[:6]:
            rev = "[green]Y[/]" if cm.reversible else "[red]N[/]"
            table.add_row(
                str(cm.priority),
                cm.action_type,
                cm.target[:16],
                cm.description[:40],
                rev,
            )

        return Panel(
            table,
            title=f"[bold blue]Blue Agent — {len(b.countermeasures)} Countermeasures[/]",
            border_style="blue",
        )

    def _render_deception(self) -> Panel:
        if not self._active_deception:
            return Panel(
                Align.center(Text("Waiting for Deception Weaver…", style="dim italic"), vertical="middle"),
                title="[bold magenta]Deception Weaver[/]",
                border_style="magenta",
                height=8,
            )

        d = self._active_deception
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Type", width=20, style="magenta")
        table.add_column("Lure")
        table.add_column("Location", width=22)

        for asset in d.assets[:5]:
            table.add_row(
                asset.asset_type,
                asset.lure_description[:35],
                asset.deployment_location[:20],
            )

        return Panel(
            table,
            title=f"[bold magenta]Deception Weaver — {len(d.assets)} Assets | {d.time_window}[/]",
            border_style="magenta",
        )

    def _render_timeline(self) -> Panel:
        lines = list(self._timeline)[-20:]
        if not lines:
            lines = ["[dim italic]Waiting for events…[/]"]
        return Panel(
            "\n".join(lines),
            title="[bold]Event Timeline[/]",
            border_style="white",
        )

    def build_layout(self) -> Group:
        return Group(
            self._render_header(),
            Columns(
                [self._render_agents(), self._render_narrative()],
                equal=True,
            ),
            Columns(
                [self._render_simulation(), self._render_blue()],
                equal=True,
            ),
            self._render_deception(),
            self._render_timeline(),
        )

    # ── Live context manager ──────────────────────────────────────────────────

    def start_live(self) -> Live:
        self._live = Live(
            self.build_layout(),
            console=self.console,
            refresh_per_second=4,
            screen=False,
        )
        return self._live

    def refresh(self) -> None:
        if self._live:
            self._live.update(self.build_layout())

    def print_final_report(self, report: IncidentReport) -> None:
        """Print a final structured report after the live display closes."""
        self.console.print()
        self.console.rule("[bold cyan]INCIDENT CLOSED — FINAL REPORT[/]", style="cyan")

        if report.narrative:
            n = report.narrative
            self.console.print(
                Panel(
                    f"[bold]{n.summary}[/]\n\n"
                    f"[dim]Intent:[/] {n.attacker_intent}\n"
                    f"[dim]Stage:[/] {n.kill_chain_stage}\n"
                    f"[dim]Techniques:[/] {', '.join(t.id for t in n.mitre_techniques)}\n"
                    f"[dim]IOCs:[/] {', '.join(n.iocs[:5])}",
                    title="[yellow]Threat Narrative[/]",
                    border_style="yellow",
                )
            )

        if report.blue_response:
            b = report.blue_response
            cm_text = "\n".join(
                f"  [{cm.priority}] [{cm.action_type}] {cm.target} — {cm.description}"
                for cm in b.countermeasures[:8]
            )
            self.console.print(
                Panel(
                    f"[bold]Strategy:[/] {b.overall_strategy}\n\n"
                    f"[bold]Actions:[/]\n{cm_text}\n\n"
                    f"[dim]Expected outcome:[/] {b.expected_outcome}\n"
                    f"[dim]Residual risk:[/] {b.residual_risk}",
                    title="[blue]Countermeasures[/]",
                    border_style="blue",
                )
            )

        if report.threat_dna:
            d = report.threat_dna
            self.console.print(
                Panel(
                    f"[bold]Scenario:[/] {d.scenario_name}\n"
                    f"[bold]Hash:[/] {d.fingerprint_hash}\n"
                    f"[bold]Effectiveness:[/] {d.effectiveness_score:.0%}\n"
                    f"[bold]Prediction:[/] {d.prediction_for_variants}\n\n"
                    f"[dim]Summary:[/] {d.incident_summary}",
                    title=f"[green]Threat DNA — {d.fingerprint_hash}[/]",
                    border_style="green",
                )
            )

        self.console.print(
            f"\n[bold green]Total pipeline time:[/] {report.duration_seconds:.1f}s\n"
        )
