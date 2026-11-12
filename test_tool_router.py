#!/usr/bin/env python3
"""
Standalone tool-router test — run this directly:

    cd ares_x_v9
    python3 test_tool_router.py

Tests that varied, casual phrasing (not exact keyword matches) still
gets routed to the correct tool by Gemini's function-calling — this is
the actual thing the rebuild was supposed to fix. Does NOT execute the
real tools (network scans etc.) — just confirms tool SELECTION is
correct, using a mocked handler that records what was called instead
of actually running it.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import api_keys
api_keys.load_keys_into_environment()

import tool_router

# Replace real handlers with recorders so this test doesn't actually
# scan anything or hit real backend state — we're testing SELECTION,
# not execution.
called: list[tuple[str, dict]] = []

async def _mock_handler(args, _name):
    called.append((_name, args))
    return {"mocked": True, "tool": _name, "args": args}

import functools
for name in list(tool_router.TOOL_HANDLERS.keys()):
    tool_router.TOOL_HANDLERS[name] = functools.partial(_mock_handler, _name=name)


TEST_CASES = [
    # (casual phrasing, expected tool name)
    ("can you check if studyguard.com has any exposed secrets on their github",
     "github_secret_scan"),
    ("hey what do you know about apt29",
     "threat_actor_profile"),
    ("is CVE-2024-3400 something i should worry about",
     "cve_lookup"),
    ("go poke around example.com and see what's exposed",
     "recon_scan"),
    ("pull out any IPs or domains from this: contacted 8.8.8.8 and evil.com",
     "extract_iocs"),
    ("what other infrastructure is connected to evil-domain.com",
     "infra_pivot"),
    ("start tracking an investigation into a phishing campaign",
     "create_mission"),
    ("what's currently active",
     "list_missions"),
    ("let it run on its own for the next 3 hours",
     "open_auth_window"),
    ("how are you doing / are you online",
     "system_status"),
    # Desktop automation — natural phrasing, no exact keywords
    ("can you take a screenshot of what's on screen right now",
     "take_screenshot"),
    ("go ahead and open burp suite for me",
     "open_application"),
    ("switch to the next window",
     "switch_window"),
    # Casual, no tool expected
    ("hey ares what can you do?",
     None),
    ("thanks that's helpful",
     None),
]


async def main():
    print(f"Testing {len(TEST_CASES)} phrasings against live Gemini tool-calling...\n")
    correct = 0
    for message, expected_tool in TEST_CASES:
        called.clear()
        try:
            response = await tool_router.route_message(message)
        except Exception as e:
            print(f"  ✗ ERROR on '{message[:50]}...': {e}")
            continue

        actual_tool = called[0][0] if called else None
        match = actual_tool == expected_tool
        correct += match
        status = "✓" if match else "✗"
        print(f"  {status} '{message[:55]}'")
        print(f"      expected={expected_tool}  got={actual_tool}")
        if not match:
            print(f"      response preview: {response[:150]}")
        print()

    print(f"{'='*60}")
    print(f"Correct tool selection: {correct}/{len(TEST_CASES)}")
    if correct == len(TEST_CASES):
        print("✅ All phrasings routed correctly — natural language tool selection works")
    else:
        print("⚠️  Some phrasings did not route as expected — see details above")


if __name__ == "__main__":
    asyncio.run(main())
