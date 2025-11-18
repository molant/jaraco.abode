"""Mock CMS/Security Panel Responses."""

from collections.abc import Mapping
from typing import Any


def get_security_panel_response(test_mode_active=False) -> Mapping[str, Any]:
    """Return security panel response json with test mode status."""
    return {
        "id": "B0:C5:CA:3A:A4:84",
        "siteId": "66236d79648c458bba0476051f7d9fed",
        "type": "1",
        "state": {
            "panelMode": "STANDBY",
            "currentAlarms": [],
            "cellConnected": False,
            "cellSignalStrength": "9",
        },
        "health": {"connectivity": "OK", "faults": []},
        "attributes": {
            "home": {"entryTimerInSeconds": 60, "exitTimerInSeconds": 60},
            "away": {"entryTimerInSeconds": 60, "exitTimerInSeconds": 60},
            "cms": {
                "vendorId": 2,
                "vendor": "rrms",
                "testModeActive": test_mode_active,
                "customSettings": True,
                "monitoringActive": True,
                "faults": [],
                "pin": "1234",
            },
        },
    }


def post_cms_settings_response(test_mode_active=True) -> Mapping[str, Any]:
    """Return CMS settings update response json."""
    return {
        "monitoringActive": True,
        "testModeActive": test_mode_active,
        "sendMedia": True,
        "dispatchWithoutVerification": True,
        "dispatchPolice": True,
        "dispatchFire": True,
        "dispatchMedical": True,
    }
