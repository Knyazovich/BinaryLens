"""Classifies imported APIs into capability categories.

This module answers "what can this binary apparently do?" -- it never
answers "is this binary dangerous?". A capability appearing here never
by itself contributes to a Finding's severity; see correlation.py for
where capabilities get turned into (or ruled out from becoming) findings.
"""

from __future__ import annotations

from typing import Dict, List

from binarylens.analysis import imports as api
from binarylens.analysis.findings import new_capability
from binarylens.models import Capability, ImportEntry

CATEGORY_PROCESS_MANAGEMENT = "Process Management"
CATEGORY_MEMORY_MANAGEMENT = "Memory Management"
CATEGORY_FILE_SYSTEM = "File System"
CATEGORY_REGISTRY = "Registry"
CATEGORY_SERVICE_MANAGEMENT = "Service Management"
CATEGORY_NETWORKING = "Networking"
CATEGORY_DYNAMIC_LINKING = "Dynamic Linking"
CATEGORY_CRYPTOGRAPHY = "Cryptography"
CATEGORY_PRIVILEGE_TOKEN = "Privilege / Token Management"
CATEGORY_ANTI_DEBUG = "Debugging / Anti-Debugging"
CATEGORY_GUI = "GUI"
CATEGORY_SYSTEM_INFO = "System Information"
CATEGORY_THREADING = "Threading / Synchronization"

# Fixed display order -- keeps terminal/JSON output stable and readable
# regardless of dict iteration order.
CATEGORY_ORDER = [
    CATEGORY_PROCESS_MANAGEMENT,
    CATEGORY_MEMORY_MANAGEMENT,
    CATEGORY_DYNAMIC_LINKING,
    CATEGORY_FILE_SYSTEM,
    CATEGORY_REGISTRY,
    CATEGORY_SERVICE_MANAGEMENT,
    CATEGORY_NETWORKING,
    CATEGORY_CRYPTOGRAPHY,
    CATEGORY_PRIVILEGE_TOKEN,
    CATEGORY_ANTI_DEBUG,
    CATEGORY_THREADING,
    CATEGORY_SYSTEM_INFO,
    CATEGORY_GUI,
]

# Ordered so the first matching set wins where an API could conceptually
# fit more than one bucket (e.g. VirtualAllocEx is both "memory" and
# "cross-process" -- we file it under Memory Management as the capability,
# and let correlation.py handle the cross-process *pattern*).
_CATEGORY_SOURCES = [
    (CATEGORY_PROCESS_MANAGEMENT, api.PROCESS_HANDLE_APIS | api.PROCESS_EXECUTION_APIS),
    (CATEGORY_MEMORY_MANAGEMENT, api.MEMORY_ALLOC_LOCAL_APIS | api.MEMORY_ALLOC_REMOTE_APIS),
    (CATEGORY_DYNAMIC_LINKING, api.DYNAMIC_RESOLUTION_APIS),
    (CATEGORY_FILE_SYSTEM, api.FILE_SYSTEM_APIS),
    (CATEGORY_REGISTRY, api.REGISTRY_READ_APIS | api.REGISTRY_WRITE_APIS),
    (CATEGORY_SERVICE_MANAGEMENT, api.SERVICE_MANAGEMENT_APIS),
    (CATEGORY_NETWORKING, api.NETWORK_APIS),
    (CATEGORY_CRYPTOGRAPHY, api.CRYPTOGRAPHY_APIS),
    (CATEGORY_PRIVILEGE_TOKEN, api.PRIVILEGE_TOKEN_APIS),
    (CATEGORY_ANTI_DEBUG, api.DEBUGGER_DETECTION_APIS | api.TIMING_APIS),
    (CATEGORY_THREADING, api.THREADING_APIS | api.REMOTE_THREAD_APIS),
    (CATEGORY_SYSTEM_INFO, api.SYSTEM_INFO_APIS),
    (CATEGORY_GUI, api.GUI_APIS),
]


def build_api_category_map() -> Dict[str, str]:
    """Flatten _CATEGORY_SOURCES into a single api-name -> category dict."""
    mapping: Dict[str, str] = {}
    for category, api_set in _CATEGORY_SOURCES:
        for name in api_set:
            mapping.setdefault(name, category)
    return mapping


API_CATEGORY_MAP = build_api_category_map()


def categorize_imports(imports: List[ImportEntry]) -> List[Capability]:
    """Group every recognized imported function into its capability
    category. Unrecognized functions are simply not categorized -- this
    is a capability inventory, not an attempt to classify every import."""
    grouped: Dict[str, set] = {}

    for entry in imports:
        for func in entry.functions:
            base = func.split("@")[0]
            category = API_CATEGORY_MAP.get(base)
            if category is None:
                continue
            grouped.setdefault(category, set()).add(base)

    capabilities = []
    for category in CATEGORY_ORDER:
        if category in grouped:
            capabilities.append(new_capability(category, sorted(grouped[category])))

    return capabilities
