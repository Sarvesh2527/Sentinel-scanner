"""
VAPT Scanning Engine
--------------------
Each security check is an independent function that takes a target URL and
returns a structured result. The web backend calls these one by one.

Owned by: Sarvesh (VAPT / Security Engineer)
"""

from .engine import run_all_checks, CHECK_REGISTRY

__all__ = ["run_all_checks", "CHECK_REGISTRY"]
