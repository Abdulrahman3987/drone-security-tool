"""
Utility helpers for the Drone Security Assessment Tool.
"""
from __future__ import annotations

import logging
import platform
import subprocess
from dataclasses import dataclass
from statistics import mean
from typing import Iterable, List, Optional


def get_logger(name: str = "drone_security_tool") -> logging.Logger:
    """
    Create or return a configured logger.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


LOGGER = get_logger()


def run_command(command: List[str], timeout: int = 10) -> str:
    """
    Run a subprocess command and return stdout as a decoded string.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.stderr:
            LOGGER.debug("Command stderr: %s", result.stderr.strip())
        return result.stdout
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        LOGGER.warning("Command %s failed: %s", command, exc)
        return ""


def average(values: Iterable[float]) -> Optional[float]:
    """
    Return the average of the provided values or None if no values were given.
    """
    values = list(values)
    return mean(values) if values else None


def current_platform() -> str:
    """
    Provide a short platform descriptor helpful for conditional logic.
    """
    sys_platform = platform.system().lower()
    if "windows" in sys_platform:
        return "windows"
    if "linux" in sys_platform:
        return "linux"
    if "darwin" in sys_platform or "mac" in sys_platform:
        return "mac"
    return sys_platform


@dataclass
class DroneTarget:
    """
    Simple container describing a drone target discovered during scanning.
    """

    ssid: str
    ip_address: Optional[str] = None
    model_hint: Optional[str] = None


def friendly_join(items: Iterable[str]) -> str:
    """
    Join items into a user-friendly comma separated string.
    """
    items = [item for item in items if item]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"
