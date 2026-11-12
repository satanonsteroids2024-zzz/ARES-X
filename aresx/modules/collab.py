"""
ARES X v6 — Collaboration & C2  [Features 71-74]
================================================
• Encrypted peer-to-peer mesh (X25519 + ChaCha20-Poly1305 via PyNaCl)
• Shared investigation workspaces (union-merge / last-write CRDT-lite)
• Dead-drop system (public-key sealed-box file exchange)
• Chain-of-custody logging (SHA-256 hash chain, tamper-evident)

All encryption uses audited primitives from PyNaCl (libsodium). There is
no central server — keys live locally, peers connect directly.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List

_KEY_DIR = Path(__file__).resolve().parent.parent.parent / "keys"
_KEY_DIR.mkdir(exist_ok=True)
_DROP_DIR = Path(__file__).resolve().parent.parent.parent / "dead_drops"
_DROP_DIR.mkdir(exist_ok=True)
_CUSTODY_FILE = Path(__file__).resolve().parent.parent.parent / "custody_chain.json"


# ──────────────────────────────────────────────────────────────
# Key management (shared by mesh + dead drop)
# ──────────────────────────────────────────────────────────────
def _ensure_keypair():
    """Load or create this node's X25519 keypair."""
    from nacl.public import PrivateKey
    priv_path = _KEY_DIR / "node_private.key"
    if priv_path.exists():
        sk = PrivateKey(priv_path.read_bytes())
    else:
        sk = PrivateKey.generate()
        priv_path.write_bytes(bytes(sk))
        priv_path.chmod(0o600)
    return sk


# ──────────────────────────────────────────────────────────────
# 71. Encrypted Peer-to-Peer Mesh
# ──────────────────────────────────────────────────────────────
def p2p_mesh(action: str, peer: str = "", message: str = "") -> None:
    """
    action: id (show my public key) | send (encrypt msg to peer pubkey) |
            open (decrypt a received blob in `message`)
    """
    from ..core import speak, show, err

    show("thinking")
    try:
        from nacl.public import PublicKey, Box
        from nacl.encoding import Base64Encoder
    except Exception:
        speak("PyNaCl not installed. Run: pip install pynacl")
        return

    sk = _ensure_keypair()
    a = action.lower()

    if a == "id":
        pub_b64 = sk.public_key.encode(Base64Encoder).decode()
        speak(f"Your ARES node public key: {pub_b64}")
        return

    if a == "send":
        if not peer or not message:
            speak("Need peer public key and a message to send.")
            return
        try:
            peer_pub = PublicKey(peer.encode(), encoder=Base64Encoder)
            box = Box(sk, peer_pub)
            ct = box.encrypt(message.encode(), encoder=Base64Encoder).decode()
            from .actions import clipboard_set
            clipboard_set(ct)
            speak(f"Encrypted message ready and copied to clipboard "
                  f"({len(ct)} chars). Send it to your peer over any channel.")
        except Exception as e:
            err(f"P2P encrypt: {e}")
        return

    if a == "open":
        if not message:
            speak("Paste the encrypted blob to decrypt.")
            return
        try:
            # peer is the sender's pubkey
            peer_pub = PublicKey(peer.encode(), encoder=Base64Encoder)
            box = Box(sk, peer_pub)
            pt = box.decrypt(message.encode(), encoder=Base64Encoder).decode()
            speak(f"Decrypted message: {pt[:300]}")
        except Exception as e:
            err(f"P2P decrypt: {e}")
        return

    speak("Usage: id | send <peer_pubkey> <message> | open <sender_pubkey> <blob>")


# ──────────────────────────────────────────────────────────────
# 72. Shared Investigation Workspaces
# ──────────────────────────────────────────────────────────────
def shared_investigation(action: str, name: str = "", data: str = "") -> None:
    """
    action: create | merge | show
    Union-merge entities into a shared workspace (CRDT-lite, conflict-free).
    """
    from ..core import speak, show, mike

    show("thinking")
    a = action.lower()
    key = f"shared_invest:{name.strip().lower()}"

    if a == "create" and name:
        mike.remember(key, json.dumps({"name": name, "entities": [],
                                       "created": time.time()}),
                      tags=["collab", "shared"])
        speak(f"Shared workspace '{name}' created. Teammates can merge into it.")
        return

    if a == "merge" and name and data:
        existing = mike.recall(key)
        ws = json.loads(existing) if existing else {"name": name, "entities": []}
        try:
            incoming = json.loads(data) if data.startswith(("[", "{")) else [data]
        except Exception:
            incoming = [data]
        incoming = incoming if isinstance(incoming, list) else [incoming]
        merged = list({*ws.get("entities", []), *[str(x) for x in incoming]})
        ws["entities"] = merged
        ws["updated"] = time.time()
        mike.remember(key, json.dumps(ws), tags=["collab", "shared"])
        speak(f"Merged {len(incoming)} items into '{name}'. "
              f"Workspace now has {len(merged)} entities.")
        return

    if a == "show" and name:
        existing = mike.recall(key)
        if not existing:
            speak(f"No shared workspace named '{name}'.")
            return
        ws = json.loads(existing)
        ents = ws.get("entities", [])
        speak(f"'{name}' has {len(ents)} entities: {', '.join(map(str, ents[:8]))}")
        return

    speak("Usage: create <name> | merge <name> <json> | show <name>")


# ──────────────────────────────────────────────────────────────
# 73. Dead Drop System
# ──────────────────────────────────────────────────────────────
def dead_drop(action: str, filepath: str = "", recipient_pubkey: str = "") -> None:
    """
    action: drop (encrypt file for recipient) | pickup (decrypt a .ares blob)
    Uses sealed boxes — only the recipient's private key can open it.
    """
    from ..core import speak, show, err

    show("thinking")
    try:
        from nacl.public import PublicKey, SealedBox
        from nacl.encoding import Base64Encoder
    except Exception:
        speak("PyNaCl not installed. Run: pip install pynacl")
        return

    a = action.lower()

    if a == "drop":
        p = Path(filepath).expanduser()
        if not p.exists():
            speak(f"File not found: {filepath}")
            return
        if not recipient_pubkey:
            speak("Need recipient public key.")
            return
        try:
            pub = PublicKey(recipient_pubkey.encode(), encoder=Base64Encoder)
            sealed = SealedBox(pub)
            ct = sealed.encrypt(p.read_bytes())
            out = _DROP_DIR / f"{p.name}.ares"
            out.write_bytes(ct)
            speak(f"File encrypted to {out.name} ({len(ct)} bytes). "
                  "Only the recipient can open it. Zero sender metadata embedded.")
        except Exception as e:
            err(f"Dead drop encrypt: {e}")
        return

    if a == "pickup":
        p = Path(filepath).expanduser()
        if not p.exists():
            speak(f"Blob not found: {filepath}")
            return
        try:
            sk = _ensure_keypair()
            sealed = SealedBox(sk)
            pt = sealed.decrypt(p.read_bytes())
            out = p.with_suffix("").with_name(p.stem.replace(".ares", "") + "_recovered")
            out.write_bytes(pt)
            speak(f"Recovered {len(pt)} bytes → {out.name}.")
        except Exception as e:
            err(f"Dead drop decrypt: {e}")
        return

    speak("Usage: drop <file> <recipient_pubkey> | pickup <blob.ares>")


# ──────────────────────────────────────────────────────────────
# 74. Chain of Custody Logging
# ──────────────────────────────────────────────────────────────
def chain_of_custody(action: str, evidence_path: str = "") -> None:
    """
    action: add (hash + log evidence) | verify (check chain integrity) | list
    Builds a tamper-evident SHA-256 hash chain (each entry links the prior).
    """
    from ..core import speak, show

    show("thinking")
    a = action.lower()
    chain: List[Dict] = []
    if _CUSTODY_FILE.exists():
        try:
            chain = json.loads(_CUSTODY_FILE.read_text(encoding="utf-8"))
        except Exception:
            chain = []

    if a == "add" and evidence_path:
        p = Path(evidence_path).expanduser()
        if not p.exists():
            speak(f"Evidence not found: {evidence_path}")
            return
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        prev_hash = chain[-1]["entry_hash"] if chain else "0" * 64
        entry = {
            "file": p.name,
            "sha256": digest,
            "collected_at": time.time(),
            "prev_hash": prev_hash,
        }
        entry["entry_hash"] = hashlib.sha256(
            (json.dumps(entry, sort_keys=True)).encode()).hexdigest()
        chain.append(entry)
        _CUSTODY_FILE.write_text(json.dumps(chain, indent=2), encoding="utf-8")
        speak(f"Evidence '{p.name}' logged. SHA-256 {digest[:12]}…, "
              f"chain length {len(chain)}.")
        return

    if a == "verify":
        if not chain:
            speak("Custody chain is empty.")
            return
        ok = True
        prev = "0" * 64
        for e in chain:
            recomputed = {k: e[k] for k in ("file", "sha256", "collected_at", "prev_hash")}
            h = hashlib.sha256(json.dumps(recomputed, sort_keys=True).encode()).hexdigest()
            if h != e["entry_hash"] or e["prev_hash"] != prev:
                ok = False
                break
            prev = e["entry_hash"]
        speak("✅ Custody chain intact — no tampering detected." if ok
              else "⚠ Custody chain BROKEN — evidence may have been altered.")
        return

    if a == "list":
        if not chain:
            speak("Custody chain is empty.")
            return
        speak(f"{len(chain)} evidence items: " +
              ", ".join(e["file"] for e in chain[:6]))
        return

    speak("Usage: add <file> | verify | list")
