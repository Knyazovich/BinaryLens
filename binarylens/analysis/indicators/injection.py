"""Process injection correlation rules.

No single API here (OpenProcess, VirtualAllocEx, WriteProcessMemory,
CreateRemoteThread, ...) is treated as suspicious in isolation -- every
one of them is also completely normal in debuggers, profilers,
installers that manage other processes, and language runtimes. A finding
is only produced when enough of the *chain* is present together.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis import imports as api
from binarylens.analysis.findings import new_finding
from binarylens.analysis.indicators.api_categories import CATEGORY_PROCESS_MANAGEMENT
from binarylens.models import Finding

# The four stages of the classic remote code injection chain: get a
# handle on another process, allocate memory in it, write shellcode/data
# into that memory, then start execution there.
_STAGE_HANDLE = api.PROCESS_HANDLE_APIS
_STAGE_ALLOC_REMOTE = api.MEMORY_ALLOC_REMOTE_APIS
_STAGE_WRITE_REMOTE = api.PROCESS_MEMORY_WRITE_APIS
_STAGE_EXECUTE_REMOTE = api.REMOTE_THREAD_APIS


def detect_injection_patterns(found_apis: set) -> List[Finding]:
    stages_present = {
        "process handle acquisition": sorted(found_apis & _STAGE_HANDLE),
        "remote memory allocation": sorted(found_apis & _STAGE_ALLOC_REMOTE),
        "remote memory write": sorted(found_apis & _STAGE_WRITE_REMOTE),
        "remote thread / execution": sorted(found_apis & _STAGE_EXECUTE_REMOTE),
    }
    stages_matched = [name for name, apis_found in stages_present.items() if apis_found]
    evidence = sorted({a for apis_found in stages_present.values() for a in apis_found})

    if not evidence:
        return []

    if len(stages_matched) >= 4:
        return [
            new_finding(
                severity="HIGH",
                name="Strong process injection pattern",
                description=(
                    "The binary imports a complete chain of APIs commonly used to "
                    "inject and execute code inside another process: acquiring a "
                    "process handle, allocating remote memory, writing to it, and "
                    "starting execution there. Debuggers, sandboxes, and some "
                    "legitimate system tools use the same chain, but this "
                    "combination is a strong behavioral signal worth reviewing."
                ),
                evidence=evidence,
                confidence="High",
                category=CATEGORY_PROCESS_MANAGEMENT,
                stages_matched=stages_matched,
            )
        ]

    if len(stages_matched) == 3:
        return [
            new_finding(
                severity="MEDIUM",
                name="Possible process injection pattern",
                description=(
                    "The binary imports most of a common cross-process code "
                    "injection chain (process handle, remote memory operations, "
                    "and/or remote execution), but not the complete pattern. This "
                    "is suggestive, not conclusive -- these APIs are also used by "
                    "legitimate process-management and debugging tools."
                ),
                evidence=evidence,
                confidence="Medium",
                category=CATEGORY_PROCESS_MANAGEMENT,
                stages_matched=stages_matched,
            )
        ]

    # One or two stages present: not enough correlation for a dedicated
    # finding. The APIs still show up as ordinary capabilities.
    return []
