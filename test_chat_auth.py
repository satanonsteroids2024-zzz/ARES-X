#!/usr/bin/env python3
"""
Standalone chat-authorization test — run this directly:

    cd ares_x_v9
    python3 test_chat_auth.py

Verifies the full "ARES asks in chat, you say yes/no in chat" flow
against LIVE Gemini tool-calling — this is the thing test_tool_router.py
doesn't cover, since it mocks tool selection entirely. This test lets
Gemini genuinely pick a gated tool (e.g. recon_scan), confirms ARES
asks a real chat-native question instead of blocking on terminal
input(), then answers it and confirms the ORIGINAL request actually
gets carried out — not just unlocked for some later, separate attempt.

Mocks tool EXECUTION (so nothing is actually scanned/reached over the
network) but not tool SELECTION or the authorization/pending logic —
those run for real, exactly as they would through the actual server.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import api_keys
api_keys.load_keys_into_environment()

from aresx.red import get_shared_authorization
# Force chat mode explicitly, same as ares_server.py does at boot —
# this test runs standalone, not through ares_server.py, so nothing
# else has set this yet.
get_shared_authorization(mode="chat")

import tool_router

# Mock only the underlying scan functions (so nothing is actually
# reached over the network) — NOT the _tool_* wrapper functions
# themselves, since those contain the real authorization-gate logic
# this test needs to exercise for real.
_scan_calls: list[tuple[str, dict]] = []


async def _fake_full_recon(target):
    _scan_calls.append(("full_recon", {"target": target}))
    return {"target": target, "mocked": True, "subdomains": [], "open_ports": []}


async def main():
    import aresx.red as red_pkg
    red_pkg.full_recon = _fake_full_recon
    # Also patch the reference tool_router's handler actually imports
    # from — it does `from aresx.red import full_recon` INSIDE the
    # handler function, so patching aresx.red's attribute is enough;
    # no need to patch tool_router's own namespace.

    print("=" * 60)
    print("STEP 1 — Gemini picks a gated tool for a natural phrasing")
    print("=" * 60)
    message = "can you scan example.com and see what's exposed"
    response = await tool_router.route_message(message)
    print(f"You: {message}")
    print(f"ARES: {response}\n")

    auth = get_shared_authorization()
    pending = auth.list_pending()

    if not pending:
        print("⚠️  No pending authorization request was created.")
        print("    Either Gemini didn't select a gated tool (check the response above")
        print("    to see what it actually did), or something is misconfigured.")
        print("    If GEMINI_API_KEY isn't set, this test can't proceed — check")
        print("    ~/.config/ares-x/env has a working key.")
        return

    print(f"✓ ARES asked in chat instead of blocking on terminal input — as it should")
    print(f"✓ Pending request tracked: {pending[0].action_label} against {pending[0].target_label}\n")

    print("=" * 60)
    print("STEP 2 — Answer 'yes' in chat, confirm it actually retries the scan")
    print("=" * 60)
    response2 = await tool_router.route_message("yes")
    print(f"You: yes")
    print(f"ARES: {response2}\n")

    if _scan_calls:
        print(f"✅ Confirmed: saying 'yes' actually re-ran the original scan")
        print(f"   Mocked call recorded: {_scan_calls[0]}")
    else:
        print(f"⚠️  'yes' did not result in the scan actually being attempted.")
        print(f"    This would be a real bug — the whole point of the retry")
        print(f"    mechanism is that approval resumes the original request.")

    still_pending = auth.list_pending()
    if still_pending:
        print(f"⚠️  Request is still marked pending after answering — should be resolved.")
    else:
        print(f"✓ Pending request correctly cleared after being answered")

    print()
    print("=" * 60)
    print("STEP 3 — Decline path: a second gated request, answered 'no'")
    print("=" * 60)
    _scan_calls.clear()
    response3 = await tool_router.route_message("scan a-different-target.com")
    print(f"You: scan a-different-target.com")
    print(f"ARES: {response3}\n")

    pending2 = auth.list_pending()
    if not pending2:
        print("⚠️  No pending request for the second scan — can't test decline path.")
        return

    response4 = await tool_router.route_message("no")
    print(f"You: no")
    print(f"ARES: {response4}\n")

    if _scan_calls:
        print(f"⚠️  Declining still resulted in the scan running — this would be a real bug.")
    else:
        print(f"✅ Confirmed: declining correctly did NOT run the scan")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("If all steps above show ✅/✓ with no ⚠️, the full chat-based")
    print("authorization flow — ARES asking in chat, you answering in")
    print("chat, approval genuinely resuming the original request — is")
    print("confirmed working end to end against live Gemini tool-calling.")


if __name__ == "__main__":
    asyncio.run(main())
