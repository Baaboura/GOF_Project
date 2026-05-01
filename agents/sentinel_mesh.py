"""
Layer 1 — Sentinel Mesh
========================
Four lightweight sensor agents monitor different attack surfaces and emit
ThreatEvent objects onto the event bus.

Real-mode sensors (network, filesystem, process) use psutil + watchdog.
Demo mode injects pre-scripted scenario events so the full agent pipeline
can be demonstrated without any actual threat.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import psutil

from core.event_bus import Topic, event_bus
from core.models import ThreatEvent

logger = logging.getLogger(__name__)


# ─────────────────────────── Demo Scenarios ──────────────────────────────────
# Each scenario is a list of event payloads that will be injected in sequence.

DEMO_SCENARIOS: Dict[str, List[Dict]] = {

    "ransomware": [
        {
            "sensor_type": "network",
            "confidence": 0.55,
            "description": "Outbound connection to known C2 IP range 185.220.x.x",
            "indicators": ["beaconing over HTTPS", "unusual User-Agent", "C2 over DNS"],
            "source_ip": "10.0.0.45",
            "destination_ip": "185.220.101.47",
        },
        {
            "sensor_type": "process",
            "confidence": 0.70,
            "description": "powershell.exe spawned with base64-encoded argument by explorer.exe",
            "indicators": ["powershell -enc", "base64 encoded payload", "invoke-expression"],
            "process_name": "powershell.exe",
        },
        {
            "sensor_type": "process",
            "confidence": 0.75,
            "description": "vssadmin.exe deleting shadow copies — classic ransomware pre-encryption step",
            "indicators": ["vssadmin delete shadows", "shadow copy deletion"],
            "process_name": "vssadmin.exe",
        },
        {
            "sensor_type": "filesystem",
            "confidence": 0.92,
            "description": "Mass file rename detected: 847 files renamed with .locked extension in 12 seconds",
            "indicators": ["mass file encryption", ".locked .encrypted file extensions", "ransom note dropped"],
            "file_path": "C:/Users/Documents/",
        },
        {
            "sensor_type": "filesystem",
            "confidence": 0.98,
            "description": "README_DECRYPT.txt dropped in every directory — ransom note confirmed",
            "indicators": ["ransom note dropped", "mass file encryption"],
            "file_path": "C:/Users/Documents/README_DECRYPT.txt",
        },
    ],

    "apt_intrusion": [
        {
            "sensor_type": "network",
            "confidence": 0.50,
            "description": "Multiple failed SSH logins from 203.0.113.77 — possible brute force",
            "indicators": ["SSH failed attempts", "brute force attempt", "multiple failed logins"],
            "source_ip": "203.0.113.77",
            "destination_ip": "10.0.0.10",
        },
        {
            "sensor_type": "network",
            "confidence": 0.65,
            "description": "Successful SSH login from 203.0.113.77 — same IP after repeated failures",
            "indicators": ["login from unusual location", "off-hours authentication"],
            "source_ip": "203.0.113.77",
            "destination_ip": "10.0.0.10",
        },
        {
            "sensor_type": "process",
            "confidence": 0.80,
            "description": "procdump.exe targeting lsass.exe — credential dump in progress",
            "indicators": ["lsass dump", "procdump -ma lsass", "mimikatz"],
            "process_name": "procdump.exe",
        },
        {
            "sensor_type": "network",
            "confidence": 0.85,
            "description": "PsExec lateral movement to 10.0.0.20 and 10.0.0.30 using harvested credentials",
            "indicators": ["PsExec detected", "psexec", "RDP connection", "SMB lateral movement"],
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
        },
        {
            "sensor_type": "filesystem",
            "confidence": 0.88,
            "description": "Sensitive directory /etc/passwd and /etc/shadow read; archive created at /tmp/.data.tar.gz",
            "indicators": ["large archive created", "data compressed to temp folder", "recursive directory listing"],
            "file_path": "/tmp/.data.tar.gz",
        },
    ],

    "cryptominer": [
        {
            "sensor_type": "process",
            "confidence": 0.60,
            "description": "Unknown process svchost32.exe consuming 98% CPU — not a standard Windows process",
            "indicators": ["CPU spike to 100%", "cryptominer process", "xmrig"],
            "process_name": "svchost32.exe",
        },
        {
            "sensor_type": "network",
            "confidence": 0.72,
            "description": "Outbound connection on port 3333 to pool.minexmr.com — mining pool",
            "indicators": ["mining pool connection", "unusual outbound port 3333", "xmrig"],
            "source_ip": "10.0.0.55",
            "destination_ip": "94.130.106.58",
        },
        {
            "sensor_type": "process",
            "confidence": 0.78,
            "description": "Registry run key modified to persist miner across reboots",
            "indicators": ["registry run key modified", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            "process_name": "reg.exe",
        },
        {
            "sensor_type": "filesystem",
            "confidence": 0.81,
            "description": "Antivirus exclusion path added for C:/Windows/Temp/svc — defender tampered",
            "indicators": ["antivirus disabled", "Set-MpPreference -DisableRealtimeMonitoring", "defender tampered"],
            "file_path": "C:/Windows/Temp/svc/",
        },
    ],
}


# ─────────────────────────── Sensor base ─────────────────────────────────────

class Sensor:
    """Minimal sensor interface."""

    def __init__(self, name: str, on_event: Callable[[ThreatEvent], None]) -> None:
        self.name = name
        self._on_event = on_event
        self._running = False

    def emit(self, **kwargs) -> None:
        event = ThreatEvent(raw_data=kwargs.get("raw_data", {}), **{
            k: v for k, v in kwargs.items() if k != "raw_data"
        })
        self._on_event(event)

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False


# ─────────────────────────── Real sensors ────────────────────────────────────

class NetworkSensor(Sensor):
    """Watches for unusual network connections using psutil."""

    KNOWN_BAD_PORTS = {4444, 1337, 31337, 3333, 6667, 8888}
    PRIVATE_RANGES = ("10.", "192.168.", "172.")

    async def start(self) -> None:
        await super().start()
        asyncio.create_task(self._monitor())

    async def _monitor(self) -> None:
        seen: set = set()
        while self._running:
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.status != "ESTABLISHED":
                        continue
                    if not conn.raddr:
                        continue
                    key = (conn.laddr.ip, conn.raddr.ip, conn.raddr.port)
                    if key in seen:
                        continue
                    seen.add(key)
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    is_external = not any(remote_ip.startswith(p) for p in self.PRIVATE_RANGES)
                    is_bad_port = remote_port in self.KNOWN_BAD_PORTS
                    if is_external or is_bad_port:
                        self.emit(
                            sensor_type="network",
                            confidence=0.65 if is_bad_port else 0.40,
                            description=f"Suspicious connection to {remote_ip}:{remote_port}",
                            indicators=["unusual outbound port" if is_bad_port else "external connection"],
                            raw_data={"laddr": str(conn.laddr), "raddr": str(conn.raddr)},
                            source_ip=conn.laddr.ip,
                            destination_ip=remote_ip,
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            await asyncio.sleep(5)


class ProcessSensor(Sensor):
    """Watches for suspicious new processes using psutil."""

    SUSPICIOUS_NAMES = {
        "mimikatz.exe", "procdump.exe", "vssadmin.exe",
        "wce.exe", "pwdump.exe", "meterpreter",
    }
    SUSPICIOUS_PARENTS = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

    async def start(self) -> None:
        await super().start()
        asyncio.create_task(self._monitor())

    async def _monitor(self) -> None:
        seen_pids: set = set()
        while self._running:
            try:
                for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "cpu_percent"]):
                    pid = proc.info["pid"]
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                    name = (proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                    indicators = []
                    if name in self.SUSPICIOUS_NAMES:
                        indicators.append(name)
                    if "-enc" in cmdline or "base64" in cmdline:
                        indicators.append("base64 encoded payload")
                    if "invoke-expression" in cmdline or "iex" in cmdline:
                        indicators.append("invoke-expression")

                    if indicators:
                        self.emit(
                            sensor_type="process",
                            confidence=0.75,
                            description=f"Suspicious process: {name}",
                            indicators=indicators,
                            raw_data={"pid": pid, "name": name, "cmdline": cmdline},
                            process_name=name,
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            await asyncio.sleep(3)


class FilesystemSensor(Sensor):
    """Watches a directory for suspicious file changes using watchdog."""

    async def start(self) -> None:
        await super().start()
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            sensor = self

            class _Handler(FileSystemEventHandler):
                SUSPICIOUS_EXTENSIONS = {".locked", ".encrypted", ".crypt", ".ransom", ".pay2decrypt"}
                SUSPICIOUS_NAMES = {"readme_decrypt.txt", "how_to_restore.txt", "ransom_note.txt"}

                def on_modified(self, event):
                    if event.is_directory:
                        return
                    self._check(event.src_path)

                def on_created(self, event):
                    if event.is_directory:
                        return
                    self._check(event.src_path)

                def _check(self, path: str):
                    p = Path(path)
                    indicators = []
                    if p.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
                        indicators.append("mass file encryption")
                        indicators.append(".locked .encrypted file extensions")
                    if p.name.lower() in self.SUSPICIOUS_NAMES:
                        indicators.append("ransom note dropped")
                    if indicators:
                        sensor.emit(
                            sensor_type="filesystem",
                            confidence=0.85,
                            description=f"Suspicious file activity: {path}",
                            indicators=indicators,
                            raw_data={"path": path},
                            file_path=path,
                        )

            watch_path = os.getenv("WATCH_PATH", ".")
            observer = Observer()
            observer.schedule(_Handler(), watch_path, recursive=True)
            observer.start()
            logger.info("FilesystemSensor watching %s", watch_path)
        except ImportError:
            logger.warning("watchdog not installed — FilesystemSensor disabled.")


# ─────────────────────────── Sentinel Mesh ───────────────────────────────────

class SentinelMesh:
    """
    Coordinates all sensors and publishes ThreatEvents onto the bus.
    In demo mode, injects scripted scenario events instead of real monitoring.
    """

    def __init__(self, demo_mode: bool = True, scenario: Optional[str] = None) -> None:
        self.demo_mode = demo_mode
        self.scenario_name = scenario or random.choice(list(DEMO_SCENARIOS.keys()))
        self._sensors: List[Sensor] = []
        self._event_buffer: List[ThreatEvent] = []
        self._running = False

    def _on_event(self, event: ThreatEvent) -> None:
        self._event_buffer.append(event)
        event_bus.publish_sync(Topic.THREAT_EVENT, event)
        logger.debug("[SENTINEL] %s | %s", event.sensor_type.upper(), event.description[:80])

    async def start(self) -> None:
        self._running = True
        if self.demo_mode:
            asyncio.create_task(self._run_demo_scenario())
        else:
            await self._start_real_sensors()

    async def _start_real_sensors(self) -> None:
        self._sensors = [
            NetworkSensor("network", self._on_event),
            ProcessSensor("process", self._on_event),
            FilesystemSensor("filesystem", self._on_event),
        ]
        for sensor in self._sensors:
            await sensor.start()
        logger.info("SentinelMesh: real sensors active.")

    async def _run_demo_scenario(self) -> None:
        scenario_events = DEMO_SCENARIOS[self.scenario_name]
        speed = float(os.getenv("DEMO_SPEED", "1.0"))
        logger.info("SentinelMesh: demo scenario '%s' starting.", self.scenario_name)

        for payload in scenario_events:
            await asyncio.sleep(2.0 / speed)
            event = ThreatEvent(
                raw_data=payload,
                sensor_type=payload["sensor_type"],
                confidence=payload["confidence"],
                description=payload["description"],
                indicators=payload.get("indicators", []),
                source_ip=payload.get("source_ip"),
                destination_ip=payload.get("destination_ip"),
                process_name=payload.get("process_name"),
                file_path=payload.get("file_path"),
            )
            self._on_event(event)

    async def stop(self) -> None:
        self._running = False
        for sensor in self._sensors:
            await sensor.stop()
