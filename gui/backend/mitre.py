# SPDX-License-Identifier: Apache-2.0
"""MITRE ATT&CK minimal mapping for UI enrichment.

The map keys are simplified attack labels we emit in analytics.
Values include ATT&CK tactic, technique id, and human-readable technique.
"""

from typing import Dict

MITRE_MAP: Dict[str, Dict[str, str]] = {
    # Discovery / Recon
    "scan": {
        "tactic": "Discovery",
        "techniqueId": "T1046",
        "technique": "Network Service Discovery",
    },
    "port-scan": {
        "tactic": "Discovery",
        "techniqueId": "T1046",
        "technique": "Network Service Discovery",
    },
    # Credential Access / Initial Access attempts via common services
    "service-bruteforce": {
        "tactic": "Credential Access",
        "techniqueId": "T1110",
        "technique": "Brute Force",
    },
    # Lateral Movement / RDP brute
    "rdp-bruteforce": {
        "tactic": "Credential Access",
        "techniqueId": "T1110",
        "technique": "Brute Force",
    },
    # Default fallback
    "unknown": {
        "tactic": "Discovery",
        "techniqueId": "T1046",
        "technique": "Network Service Discovery",
    },
}


def map_attack(attack_type: str) -> Dict[str, str]:
    """Return MITRE fields for given attack label.

    If unknown, fall back to a safe default (Discovery/T1046) to keep UI stable.
    """
    return MITRE_MAP.get(attack_type, MITRE_MAP["unknown"]).copy()


