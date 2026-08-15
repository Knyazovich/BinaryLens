"""Persistence-mechanism correlation rules.

Registry writes and service-management APIs are each completely ordinary
on their own -- installers, updaters, and background applications use
both routinely. BinaryLens cannot see the actual registry paths or
service names being written (pefile only exposes imported *function*
names, not their runtime arguments), so this module deliberately stays
conservative: it only raises a finding when registry writes are combined
with service-management APIs, which together suggest the binary can both
persist configuration and install/control a Windows service -- still
described as "possible", never as confirmed persistence malware.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis import imports as api
from binarylens.analysis.findings import new_finding
from binarylens.analysis.indicators.api_categories import CATEGORY_REGISTRY
from binarylens.models import Finding


def detect_persistence_patterns(found_apis: set) -> List[Finding]:
    registry_writes = sorted(found_apis & api.REGISTRY_WRITE_APIS)
    service_apis = sorted(found_apis & api.SERVICE_MANAGEMENT_APIS)

    if not (registry_writes and service_apis):
        return []

    evidence = sorted(set(registry_writes) | set(service_apis))
    return [
        new_finding(
            severity="LOW",
            name="Possible persistence-related capability",
            description=(
                "The binary imports both registry-write APIs and Windows "
                "service-management APIs. Together these can be used to install "
                "and configure a persistent service, but this combination is "
                "also completely ordinary for installers and system utilities "
                "that legitimately manage services."
            ),
            evidence=evidence,
            confidence="Low",
            category=CATEGORY_REGISTRY,
        )
    ]
