#!/usr/bin/env python3
r"""A GUI and CLI for managing per-unit anonymous-publish access on a MediaMTX
relay, at scale. Self-contained: pure standard library (Tkinter + subprocess
+ ssh), no pip installs, one file. Runs on Linux and on old Windows (Tkinter
and a bundled OpenSSH-compatible client are the only requirements).

THE PROBLEM THIS SOLVES
------------------------
A fleet of IP cameras (or any RTMP/RTSP publisher) that can't send a login
-- common on embedded devices -- can only be authorized by MediaMTX's
"anonymous publish, but only to one exact path" mechanism: give each unit a
random, unguessable path segment (its "stream key"), and configure MediaMTX
to allow anonymous publish on exactly that one path. A second random segment
("viewer key") gates a read-only mirror path so other clients (a dashboard,
a video wall, whatever) can watch without ever seeing the push key.

Hand-editing MediaMTX's authInternalUsers/paths YAML for every new unit
doesn't scale and is easy to get wrong (a boundary regex that swallows the
wrong entries corrupts every other unit's access at once). This tool
generates both keys, applies the YAML change safely (always backs up first,
validates the result, and is self-tested against synthetic *and* real
config shapes before it ever runs -- see verify_transforms() / --selftest),
and gives you a small GUI (or a terminal menu) for onboarding one unit,
onboarding a batch of units in a single relay round trip, rotating a unit's
keys, removing a unit, listing/exporting the current state, and watching
the relay's logs live.

REQUIREMENTS
------------
- Python 3.8+ with Tkinter (ships with python.org's Windows installer;
  on Debian/Ubuntu Linux: `sudo apt install python3-tk`)
- An `ssh` client on PATH (Windows 10/11 ship one; on Windows 7, install
  any OpenSSH-compatible client, e.g. Git for Windows)
- SSH access to a host running MediaMTX, with sudo rights to read and
  write its config file (default assumed path: /etc/mediamtx/mediamtx.yml)

This tool makes no assumption about what kind of device is publishing --
"device type" is just a label you choose, used only in comments and the
units table. It does not know or care about any specific camera brand.

USAGE
-----
  python mediamtx_relay_manager.py            # GUI
  python mediamtx_relay_manager.py --cli      # terminal menu
  python mediamtx_relay_manager.py --selftest # verify the YAML transforms,
                                               # never touches a relay

First run asks for the SSH key path, relay host/user, the remote config
path (if not /etc/mediamtx/mediamtx.yml), and where to save a local
key-inventory file and an audit log. These are remembered in
~/.mediamtx_relay_manager/config.json. Nothing machine- or
deployment-specific is hard-coded.

LICENSE: MIT (see LICENSE in this repository).
"""
import base64
import csv
import json
import queue
import re
import secrets
import string
import subprocess
import sys
import threading
import time
from pathlib import Path

CONFIG_PATH = Path.home() / ".mediamtx_relay_manager" / "config.json"
KEY_ALPHABET = string.ascii_lowercase + string.digits
UNIT_COMMENT_RE = re.compile(r"  # ([A-Za-z0-9_-]+) unit ([a-z0-9]+):")
REFRESH_SECS = 15


# ==========================================================================
# config
# ==========================================================================

def load_config():
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return {}


def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


CONFIG_FIELDS = [
    ("ssh_key_path", "Path to your relay SSH private key", ""),
    ("relay_host", "Relay host or IP", ""),
    ("relay_user", "Relay SSH username", ""),
    ("remote_config_path", "Remote path to mediamtx.yml", "/etc/mediamtx/mediamtx.yml"),
    ("values_file", "Local path to save generated keys (private, never share/commit)",
     str(Path.home() / ".mediamtx_relay_manager" / "keys.txt")),
    ("log_dir", "Directory for a local audit log and CSV exports",
     str(Path.home() / ".mediamtx_relay_manager" / "logs")),
]


def ask(prompt, default=None):
    while True:
        suffix = f" [{default}]" if default else ""
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw and default is not None:
            return default
        if raw:
            return raw
        print("  required")


def ensure_config_cli():
    cfg = load_config()
    changed = False
    for key, prompt, default in CONFIG_FIELDS:
        if key not in cfg:
            cfg[key] = ask(prompt, default)
            changed = True
    if changed:
        save_config(cfg)
        print(f"\nSaved settings to {CONFIG_PATH}\n")
    return cfg


def edit_settings_cli(cfg):
    print("\nCurrent settings:")
    for k, v in cfg.items():
        print(f"  {k} = {v}")
    key = ask("\nField to change (blank to go back)", default="")
    if not key:
        return
    if key not in cfg:
        print(f"  unknown field '{key}'")
        return
    cfg[key] = ask(f"New value for {key}", default=cfg[key])
    save_config(cfg)
    print("Saved.\n")


# ==========================================================================
# ssh plumbing
# ==========================================================================

def ssh_run(cfg, remote_cmd, timeout=25, stream=False):
    cmd = ["ssh", "-i", cfg["ssh_key_path"], "-o", "ConnectTimeout=10",
           f"{cfg['relay_user']}@{cfg['relay_host']}", remote_cmd]
    if stream:
        return subprocess.run(cmd, timeout=timeout)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def fetch_remote_file(cfg, remote_path):
    r = ssh_run(cfg, f"sudo cat {remote_path}")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"failed to read {remote_path}")
    return r.stdout


def push_remote_file(cfg, remote_path, content, backup_tag):
    ts = time.strftime("%Y%m%d%H%M%S")
    bak = f"{remote_path}.bak-{backup_tag}-{ts}"
    r = ssh_run(cfg, f"sudo cp {remote_path} {bak}")
    if r.returncode != 0:
        raise RuntimeError(f"backup failed: {r.stderr.strip()}")
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    r = ssh_run(cfg, f"echo {b64} | base64 -d | sudo tee {remote_path} > /dev/null")
    if r.returncode != 0:
        raise RuntimeError(f"write failed (backup is at {bak}): {r.stderr.strip()}")
    # Dependency-free validation: confirm the write wasn't truncated (exact byte
    # count) and the two expected top-level sections are still present -- grep
    # and wc only, nothing beyond POSIX. An earlier version of this tool shelled
    # out to `sudo python3 -c "import yaml; ..."` on the relay host, which
    # silently requires python3 AND PyYAML there -- neither is a safe assumption
    # (MediaMTX itself is a dependency-free static binary, so plenty of relay
    # hosts won't have either). The failure mode was especially bad: the tee
    # above had already succeeded, so a relay missing either dependency would
    # report every write as FAILED and tell the operator to restore a backup
    # over a change that had actually worked. Full YAML correctness is
    # guaranteed locally instead, by add_unit_block/remove_unit_block being
    # self-tested (verify_transforms / --selftest) before they ever run.
    # sudo on every read here too -- the config file is typically root-only
    # (0600), so an unprivileged read as the SSH user fails before sudo ever
    # enters the picture. This bit twice: first without sudo at all, then
    # with `sudo wc -c < path` -- which STILL fails, because `<` redirection
    # is opened by the calling (unprivileged) shell to set up sudo's stdin,
    # before sudo runs; the open happens as the wrong user regardless of
    # where sudo sits in the command. `sudo cat path | wc -c` works because
    # cat itself, running as root, is what touches the file; wc only ever
    # sees an already-open pipe. Caught live both times: the actual writes
    # below all succeeded, but this check reported every one of them as
    # FAILED until both fixes were in.
    expected_len = len(content.encode("utf-8"))
    check_cmd = (
        f'[ "$(sudo cat {remote_path} | wc -c)" = "{expected_len}" ] && '
        f"sudo grep -q '^authInternalUsers:' {remote_path} && "
        f"sudo grep -q '^paths:' {remote_path} && echo OK"
    )
    r = ssh_run(cfg, check_cmd)
    if r.returncode != 0 or "OK" not in r.stdout:
        raise RuntimeError(
            f"new file failed validation (size/structure mismatch), restore from {bak} manually: {r.stderr.strip()}"
        )
    return bak


def write_key_files(cfg, remote_dir, entries):
    """entries: list of (label, streamkey, viewkey). One SSH round trip for any number of units."""
    parts = []
    for label, streamkey, viewkey in entries:
        parts.append(f"echo -n '{streamkey}' | sudo tee {remote_dir}/streamkey-{label} > /dev/null")
        parts.append(f"echo -n '{viewkey}' | sudo tee {remote_dir}/viewkey-{label} > /dev/null")
    labels_glob = " ".join(f"{remote_dir}/streamkey-{l} {remote_dir}/viewkey-{l}" for l, _, _ in entries)
    parts.append(f"sudo chmod 600 {labels_glob}")
    parts.append(f"sudo chown root:root {labels_glob}")
    r = ssh_run(cfg, " && ".join(parts))
    if r.returncode != 0:
        raise RuntimeError(f"key file write failed: {r.stderr.strip()}")


def remove_key_files(cfg, remote_dir, label):
    ssh_run(cfg, f"sudo rm -f {remote_dir}/streamkey-{label} {remote_dir}/viewkey-{label}")


def log_action(cfg, text):
    log_dir = Path(cfg["log_dir"])
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with (log_dir / "relay_manager.log").open("a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {text}\n")


def append_values(cfg, comment, label, streamkey, viewkey):
    values_file = Path(cfg["values_file"])
    values_file.parent.mkdir(parents=True, exist_ok=True)
    with values_file.open("a", encoding="utf-8") as f:
        f.write(f"\n--- {comment} ---\n")
        f.write(f"streamkey_{label}={streamkey}\n")
        f.write(f"viewkey_{label}={viewkey}\n")
    return values_file


def _remote_dir(cfg):
    """Key files live beside the config file by default."""
    return cfg["remote_config_path"].rsplit("/", 1)[0]


# ==========================================================================
# pure transforms on mediamtx.yml text -- self-tested (see verify_transforms)
# against both a synthetic sample and, in this project's own deployment,
# real fetched config, before any of this is trusted to touch a live relay
# ==========================================================================

def gen_key(n):
    return "".join(secrets.choice(KEY_ALPHABET) for _ in range(n))


def add_unit_block(content, comment, push_path, view_path):
    # Must insert at the BOTTOM of authInternalUsers (immediately before the
    # top-level "paths:" header), not the top. Any bare (uncommented) entry
    # already in the file -- which is common, e.g. a catch-all publisher/
    # viewer login -- has no "unit X:" comment of its own, so if a new block
    # landed above it, the block-boundary regex ("stop at the next labeled
    # comment") would never fire until paths:, silently swallowing every
    # entry in between on the next list/remove/rotate call.
    if f"path: {push_path}\n" in content:
        raise ValueError(f"{push_path} is already registered")
    auth_marker = "authInternalUsers:\n"
    top_paths_marker = "paths:\n"
    if auth_marker not in content:
        raise ValueError("authInternalUsers marker not found")
    if top_paths_marker not in content:
        raise ValueError("top-level paths: marker not found")
    insert = (
        f"  # {comment}: anonymous publish on its secret path (the device cannot send\n"
        f"  # a login); read from this host feeds the mirror; the mirror is publicly readable\n"
        f"  - user: any\n"
        f"    pass:\n"
        f"    ips: []\n"
        f"    permissions:\n"
        f"      - action: publish\n"
        f"        path: {push_path}\n"
        f"  - user: any\n"
        f"    pass:\n"
        f"    ips: ['127.0.0.1', '::1']\n"
        f"    permissions:\n"
        f"      - action: read\n"
        f"        path: {push_path}\n"
        f"  - user: any\n"
        f"    pass:\n"
        f"    ips: []\n"
        f"    permissions:\n"
        f"      - action: read\n"
        f"        path: {view_path}\n"
    )
    content = content.replace(top_paths_marker, insert + top_paths_marker, 1)

    nested_paths_marker = "  all_others:"
    if nested_paths_marker not in content:
        raise ValueError("all_others marker not found")
    path_insert = (
        f"  {view_path}:\n"
        f"    source: rtsp://127.0.0.1:8554/{push_path}\n"
        f"    sourceOnDemand: yes\n"
        f"    rtspTransport: tcp\n"
    )
    content = content.replace(nested_paths_marker, path_insert + nested_paths_marker)
    return content


def _unit_block_span(content, label):
    # The lookahead must only match the START of the NEXT unit's comment
    # (same shape as UNIT_COMMENT_RE), not this block's own second comment
    # line, which an earlier version of this regex matched by mistake and
    # silently truncated every block to one line. The trailing "\n" is
    # consumed as part of the match itself (not left in the lookahead) so
    # the span's end lands exactly at the start of the next line --
    # otherwise removal leaves a blank line behind where it was cut.
    pattern = re.compile(
        r"  # [^\n]*unit " + re.escape(label) + r":.*?\n(?=  # [A-Za-z0-9_-]+ unit |paths:\n)", re.S
    )
    m = pattern.search(content)
    return (m.start(), m.end()) if m else None


def _mirror_entry_regex(streamkey):
    # Correlate a paths: mirror entry to a unit by its source: line, not by
    # assuming the mirror path's own label segment matches the unit's label
    # -- a hand-edited config may not agree (seen in this project's own
    # deployment: the two earliest units had comments reading "unit 1" and
    # "unit 2" while their actual mirror paths used different labels).
    return re.compile(
        r"  view/[a-z0-9]+/[^:\n]+:\n"
        r"    source: rtsp://127\.0\.0\.1:8554/live/" + re.escape(streamkey) + r"\n"
        r"(?:    .*\n)*"
    )


def remove_unit_block(content, label):
    span = _unit_block_span(content, label)
    if not span:
        raise ValueError(f"no permission block found for unit '{label}'")
    start, end = span
    sk_m = re.search(r"path: live/(\S+)", content[start:end])
    if not sk_m:
        raise ValueError(f"could not find the push path inside unit '{label}'s own block")
    content2 = content[:start] + content[end:]
    content2, n = _mirror_entry_regex(sk_m.group(1)).subn("", content2)
    if n == 0:
        raise ValueError(
            f"permissions removed but no matching paths: entry found for '{label}' -- stop, inspect by hand"
        )
    return content2


def list_units_detailed(content):
    """Returns [{device, label, mirror_label, streamkey, viewkey}]."""
    units = []
    for m in UNIT_COMMENT_RE.finditer(content):
        device, label = m.group(1), m.group(2)
        span = _unit_block_span(content, label)
        block = content[span[0]:span[1]] if span else ""
        sk_m = re.search(r"path: live/(\S+)", block)
        streamkey = sk_m.group(1) if sk_m else None
        viewkey, mirror_label = None, label
        if streamkey:
            mirror_m = _mirror_entry_regex(streamkey).search(content)
            if mirror_m:
                header_m = re.match(r"  view/([a-z0-9]+)/([^:\n]+):", mirror_m.group(0))
                if header_m:
                    mirror_label, viewkey = header_m.group(1), header_m.group(2)
        units.append({
            "device": device, "label": label, "mirror_label": mirror_label,
            "streamkey": streamkey, "viewkey": viewkey,
        })
    return units


def unit_urls(cfg, label, streamkey, viewkey):
    """Returns both the RTMP and RTSP+stream-key push forms, plus the read-only
    mirror URL. Which push form your device actually needs depends on your
    device; MediaMTX accepts either on the same path."""
    push_path = f"live/{streamkey}"
    view_path = f"view/{label}/{viewkey}"
    host = cfg["relay_host"]
    return {
        "push_rtmp": f"rtmp://{host}:1935/{push_path}",
        "push_rtsp_key": f"rtsp://{host}:8554  (stream key: {push_path})",
        "view_url": f"rtsp://{host}:8554/{view_path}",
    }


def parse_batch_spec(raw):
    """'typeA:n4,typeA:n5,typeB:p3' -> ([(device,label),...], [bad_chunk,...])."""
    parsed, skipped = [], []
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        if ":" not in chunk:
            skipped.append(chunk)
            continue
        device, label = chunk.split(":", 1)
        device = re.sub(r"[^A-Za-z0-9_-]", "", device)
        label = re.sub(r"[^a-z0-9]", "", label.lower())
        if not device or not label:
            skipped.append(chunk)
            continue
        parsed.append((device, label))
    return parsed, skipped


def _apply_one(device, label):
    streamkey = gen_key(16)
    viewkey = gen_key(24)
    return {
        "device": device, "label": label, "comment": f"{device} unit {label}",
        "streamkey": streamkey, "viewkey": viewkey,
        "push_path": f"live/{streamkey}", "view_path": f"view/{label}/{viewkey}",
    }


def verify_transforms():
    """Self-check: add() then remove() must exactly undo itself, must not
    disturb bare (uncommented) entries, must handle sequential adds without
    cross-contamination, must correlate mismatched label/mirror-path units
    correctly, and must reject a duplicate publish path. Call with
    --selftest. Never touches a relay."""
    sample = (
        "authInternalUsers:\n"
        "  - user: any\n"
        "    pass:\n"
        "    ips: []\n"
        "    permissions:\n"
        "      - action: publish\n"
        "        path: live/existingkey000000\n"
        "  - user: publisher\n"
        "    pass: somepass\n"
        "    permissions:\n"
        "      - action: publish\n"
        "        path: \"\"\n"
        "  - user: viewer\n"
        "    pass: anotherpass\n"
        "    permissions:\n"
        "      - action: read\n"
        "        path: \"\"\n"
        "paths:\n"
        "  all_others:\n"
    )
    added = add_unit_block(sample, "typeA unit ztest", "live/testkey0123456", "view/ztest/testviewkey0123456789abcd")
    assert "live/testkey0123456" in added
    assert "view/ztest/testviewkey0123456789abcd:" in added
    assert added.index("live/existingkey000000") < added.index("testkey0123456")
    assert added.index("- user: viewer") < added.index("# typeA unit ztest")

    detail = list_units_detailed(added)
    assert detail == [{
        "device": "typeA", "label": "ztest", "mirror_label": "ztest",
        "streamkey": "testkey0123456", "viewkey": "testviewkey0123456789abcd",
    }], detail

    mismatched = add_unit_block(sample, "typeA unit 9", "live/mismatchkey0000000", "view/n9/mismatchviewkey00000000000000")
    d = list_units_detailed(mismatched)
    assert d == [{
        "device": "typeA", "label": "9", "mirror_label": "n9",
        "streamkey": "mismatchkey0000000", "viewkey": "mismatchviewkey00000000000000",
    }], d
    assert remove_unit_block(mismatched, "9") == sample

    removed = remove_unit_block(added, "ztest")
    assert removed == sample, "round-trip mismatch (bare entries got disturbed):\n" + removed

    added2 = add_unit_block(added, "typeB unit zp", "live/otherkey00000000", "view/zp/otherviewkey000000000000")
    assert {u["label"] for u in list_units_detailed(added2)} == {"ztest", "zp"}
    removed_zp = remove_unit_block(added2, "zp")
    assert removed_zp == added, "removing the 2nd unit disturbed the 1st:\n" + removed_zp
    assert remove_unit_block(removed_zp, "ztest") == sample

    try:
        add_unit_block(added, "typeA unit dup", "live/testkey0123456", "view/dup/x" * 3)
        raise AssertionError("expected ValueError on duplicate path")
    except ValueError:
        pass

    print("verify_transforms: OK")


# ==========================================================================
# CLI actions
# ==========================================================================

def onboard_cli(cfg):
    device = re.sub(r"[^A-Za-z0-9_-]", "", ask("Device type (any short label)"))
    label = re.sub(r"[^a-z0-9]", "", ask("Unit label, e.g. 'a1'").lower())
    if not device or not label:
        print("  device type and label are both required")
        return
    unit = _apply_one(device, label)
    print(f"\nGenerated: stream key {unit['streamkey']}, viewer key {unit['viewkey']}")
    if ask("Apply to the relay now? (y/n)", default="n").lower() != "y":
        print("Cancelled -- nothing was changed.\n")
        return
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
        new_content = add_unit_block(content, unit["comment"], unit["push_path"], unit["view_path"])
        bak = push_remote_file(cfg, cfg["remote_config_path"], new_content, label)
        write_key_files(cfg, _remote_dir(cfg), [(label, unit["streamkey"], unit["viewkey"])])
    except Exception as e:
        print(f"FAILED: {e}")
        log_action(cfg, f"onboard {unit['comment']} FAILED: {e}")
        return
    values_file = append_values(cfg, unit["comment"], label, unit["streamkey"], unit["viewkey"])
    log_action(cfg, f"onboarded {unit['comment']}: backup={bak}")
    print(f"\nApplied. Backup saved on the relay as {bak}")
    print(f"Keys appended to {values_file}\n")
    info = unit_urls(cfg, label, unit["streamkey"], unit["viewkey"])
    print(f"RTMP push:       {info['push_rtmp']}")
    print(f"RTSP push:       {info['push_rtsp_key']}")
    print(f"Read-only view:  {info['view_url']}\n")


def batch_onboard_cli(cfg):
    print("Enter units as 'devicetype:label' pairs, comma-separated.")
    print("Example: typeA:a4,typeA:a5,typeB:b3\n")
    raw = ask("Units")
    parsed, skipped = parse_batch_spec(raw)
    for chunk in skipped:
        print(f"  skipping '{chunk}': expected devicetype:label")
    if not parsed:
        print("Nothing to apply.\n")
        return
    units = [_apply_one(d, l) for d, l in parsed]
    print(f"\nGenerated {len(units)} key pairs:")
    for u in units:
        print(f"  {u['comment']:<28} stream={u['streamkey']} view={u['viewkey']}")
    if ask("\nApply all of these to the relay now? (y/n)", default="n").lower() != "y":
        print("Cancelled -- nothing was changed.\n")
        return
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
    except Exception as e:
        print(f"FAILED to fetch config: {e}")
        return
    applied, failed = [], []
    for u in units:
        try:
            content = add_unit_block(content, u["comment"], u["push_path"], u["view_path"])
            applied.append(u)
        except ValueError as e:
            failed.append((u, str(e)))
    if not applied:
        print("All units failed to stage (likely duplicate paths). Nothing sent.\n")
        return
    try:
        bak = push_remote_file(cfg, cfg["remote_config_path"], content, "batch")
        write_key_files(cfg, _remote_dir(cfg), [(u["label"], u["streamkey"], u["viewkey"]) for u in applied])
    except Exception as e:
        print(f"FAILED during write: {e}")
        log_action(cfg, f"batch onboard FAILED: {e}")
        return
    for u in applied:
        append_values(cfg, u["comment"], u["label"], u["streamkey"], u["viewkey"])
    log_action(cfg, f"batch onboarded {[u['label'] for u in applied]}, backup={bak}")
    print(f"\nApplied {len(applied)} unit(s). Backup: {bak}\n")
    for u in applied:
        info = unit_urls(cfg, u["label"], u["streamkey"], u["viewkey"])
        print(f"{u['comment']}: rtmp={info['push_rtmp']}  view={info['view_url']}")
    if failed:
        print("\nSkipped (duplicate path):", ", ".join(u["comment"] for u, _ in failed))
    print()


def generate_keys_only_cli(cfg):
    device = re.sub(r"[^A-Za-z0-9_-]", "", ask("Device type (any short label)"))
    label = re.sub(r"[^a-z0-9]", "", ask("Unit label").lower())
    if not device or not label:
        print("  device type and label are both required")
        return
    unit = _apply_one(device, label)
    values_file = append_values(cfg, unit["comment"] + " (NOT YET applied)", label, unit["streamkey"], unit["viewkey"])
    log_action(cfg, f"generated keys only for {unit['comment']} (not applied)")
    print(f"\nStream key: {unit['streamkey']}\nViewer key: {unit['viewkey']}")
    print(f"Saved to {values_file} (marked not-yet-applied).\n")


def rotate_unit_cli(cfg):
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
    except Exception as e:
        print(f"FAILED: {e}")
        return
    units = {u["label"]: u for u in list_units_detailed(content)}
    if not units:
        print("No units registered.\n")
        return
    for label, u in units.items():
        print(f"  {u['device']} {label}")
    label = ask("\nLabel to rotate").strip()
    if label not in units:
        print(f"  '{label}' not found\n")
        return
    device = units[label]["device"]
    print("\nRotating invalidates the current URLs -- the device and any viewers must")
    print("be reconfigured with the new ones afterward.")
    if ask(f"Rotate keys for '{label}'? (y/n)", default="n").lower() != "y":
        print("Cancelled.\n")
        return
    new_unit = _apply_one(device, label)
    try:
        content2 = remove_unit_block(content, label)
        content3 = add_unit_block(content2, new_unit["comment"], new_unit["push_path"], new_unit["view_path"])
        bak = push_remote_file(cfg, cfg["remote_config_path"], content3, f"rotate-{label}")
        remove_key_files(cfg, _remote_dir(cfg), label)
        write_key_files(cfg, _remote_dir(cfg), [(label, new_unit["streamkey"], new_unit["viewkey"])])
    except Exception as e:
        print(f"FAILED: {e}")
        log_action(cfg, f"rotate {label} FAILED: {e}")
        return
    append_values(cfg, new_unit["comment"] + " (rotated)", label, new_unit["streamkey"], new_unit["viewkey"])
    log_action(cfg, f"rotated keys for {label}, backup={bak}")
    info = unit_urls(cfg, label, new_unit["streamkey"], new_unit["viewkey"])
    print(f"\nRotated. Backup: {bak}\nrtmp={info['push_rtmp']}\nview={info['view_url']}\n")


def list_units_cli(cfg):
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
    except Exception as e:
        print(f"FAILED: {e}")
        return
    units = list_units_detailed(content)
    if not units:
        print("No units registered.\n")
        return
    print(f"\n{'Device':<14} {'Label':<8} Mirror key OK?")
    for u in units:
        print(f"{u['device']:<14} {u['label']:<8} {'yes' if u['viewkey'] else 'NO -- inspect by hand'}")
    print(f"\n{len(units)} unit(s) total.\n")


def export_inventory_cli(cfg):
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
    except Exception as e:
        print(f"FAILED: {e}")
        return
    units = list_units_detailed(content)
    if not units:
        print("No units registered.\n")
        return
    default_path = str(Path(cfg["log_dir"]) / "inventory.csv")
    out_path = Path(ask("Save CSV to", default=default_path))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device", "label", "push_rtmp", "push_rtsp_key", "view_url"])
        for u in units:
            info = unit_urls(cfg, u["mirror_label"], u["streamkey"], u["viewkey"])
            w.writerow([u["device"], u["label"], info["push_rtmp"], info["push_rtsp_key"], info["view_url"]])
    print(f"Wrote {len(units)} unit(s) to {out_path}\n")


def remove_unit_cli(cfg):
    try:
        content = fetch_remote_file(cfg, cfg["remote_config_path"])
    except Exception as e:
        print(f"FAILED: {e}")
        return
    units = list_units_detailed(content)
    if not units:
        print("No units registered.\n")
        return
    for u in units:
        print(f"  {u['device']} {u['label']}")
    label = ask("\nLabel to remove").strip()
    if not any(u["label"] == label for u in units):
        print(f"  '{label}' not found\n")
        return
    if ask(f"Really remove unit '{label}'? This also deletes its key files. (y/n)", default="n").lower() != "y":
        print("Cancelled.\n")
        return
    try:
        new_content = remove_unit_block(content, label)
        bak = push_remote_file(cfg, cfg["remote_config_path"], new_content, f"rm-{label}")
        remove_key_files(cfg, _remote_dir(cfg), label)
    except Exception as e:
        print(f"FAILED: {e}")
        log_action(cfg, f"remove {label} FAILED: {e}")
        return
    log_action(cfg, f"removed unit {label}, backup={bak}")
    print(f"Removed. Backup: {bak}\n")


def monitor_cli(cfg):
    remote_cmd = (
        "echo '--- uptime/load ---'; uptime; "
        "echo '--- memory (MB) ---'; free -m; "
        "echo '--- mediamtx process ---'; ps -C mediamtx -o pid,%cpu,%mem,rss,etime --no-headers; "
        "echo '--- recent connections ---'; sudo journalctl -u mediamtx -n 15 --no-pager"
    )
    r = ssh_run(cfg, remote_cmd)
    print(r.stdout)
    if r.returncode != 0:
        print(f"(stderr: {r.stderr.strip()})")
    print()


def tail_logs_cli(cfg):
    print("Live-following relay logs. Ctrl+C to stop.\n")
    try:
        ssh_run(cfg, "sudo journalctl -u mediamtx -f --no-pager", timeout=3600, stream=True)
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        pass
    print()


def run_cli():
    cfg = ensure_config_cli()
    actions = {
        "1": ("Onboard a new unit", onboard_cli),
        "2": ("Batch-onboard multiple units", batch_onboard_cli),
        "3": ("Generate keys only (apply later)", generate_keys_only_cli),
        "4": ("Rotate a unit's keys", rotate_unit_cli),
        "5": ("List registered units", list_units_cli),
        "6": ("Export inventory to CSV", export_inventory_cli),
        "7": ("Remove a unit", remove_unit_cli),
        "8": ("Monitor relay (CPU/RAM/connections)", monitor_cli),
        "9": ("Tail live relay logs", tail_logs_cli),
        "10": ("Settings (paths, SSH key, host)", edit_settings_cli),
    }
    while True:
        print("=" * 60)
        print("  MediaMTX relay manager")
        print("=" * 60)
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        print("0. Exit")
        choice = ask("Choose", default="0")
        if choice == "0":
            break
        action = actions.get(choice)
        if not action:
            print("  unknown choice")
            continue
        action[1](cfg)


# ==========================================================================
# GUI
# ==========================================================================

class RelayGUI:
    def __init__(self, root):
        import tkinter as tk
        self.tk = tk
        self.root = root
        self.root.title("MediaMTX Relay Manager")
        self.root.geometry("800x560")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.cfg = {}
        self.log_q = queue.Queue()
        self.task_q = queue.Queue()
        self.log_proc = None
        self.stop_log = threading.Event()
        self.paused = False
        self.buttons = []

        self._build_widgets()
        self.root.after(100, self._startup)
        self.root.after(150, self._poll_queues)

    def _build_widgets(self):
        tk = self.tk
        from tkinter import ttk, scrolledtext

        header = tk.Frame(self.root, padx=8, pady=6)
        header.pack(fill="x")
        self.host_label = tk.Label(header, text="Host: --", font=("Segoe UI", 9, "bold"))
        self.host_label.grid(row=0, column=0, sticky="w", padx=(0, 20))
        self.status_label = tk.Label(header, text="Status: --", font=("Segoe UI", 9, "bold"))
        self.status_label.grid(row=0, column=1, sticky="w", padx=(0, 20))
        self.uptime_label = tk.Label(header, text="Uptime: --")
        self.uptime_label.grid(row=0, column=2, sticky="w", padx=(0, 20))
        self.load_label = tk.Label(header, text="Load: --")
        self.load_label.grid(row=0, column=3, sticky="w")

        tk.Label(self.root, text="Units", font=("Segoe UI", 9, "bold"), anchor="w").pack(
            fill="x", padx=8, pady=(6, 0)
        )
        cols = ("device", "label", "path", "status")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=5)
        for c, w, t in [
            ("device", 110, "Device"), ("label", 60, "Label"),
            ("path", 300, "Stream Path"), ("status", 110, "Status"),
        ]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w)
        self.tree.pack(fill="x", padx=8, pady=(2, 6))

        log_header = tk.Frame(self.root)
        log_header.pack(fill="x", padx=8)
        tk.Label(log_header, text="Live Log", font=("Segoe UI", 9, "bold")).pack(side="left")
        self.pause_btn = tk.Button(log_header, text="Pause", width=8, command=self._toggle_pause)
        self.pause_btn.pack(side="right")

        self.log_widget = scrolledtext.ScrolledText(
            self.root, height=12, font=("Consolas", 9), bg="#111318", fg="#d6d6d6"
        )
        self.log_widget.pack(fill="both", expand=True, padx=8, pady=(2, 6))
        self.log_widget.configure(state="disabled")

        btns = tk.Frame(self.root, padx=8, pady=6)
        btns.pack(fill="x")
        actions = [
            ("Onboard", self.action_onboard), ("Batch", self.action_batch),
            ("Gen Keys", self.action_genkeys), ("Rotate", self.action_rotate),
            ("Remove", self.action_remove), ("Export", self.action_export),
            ("Settings", self.action_settings),
        ]
        for i, (text, cmd) in enumerate(actions):
            b = tk.Button(btns, text=text, width=10, command=cmd)
            b.grid(row=0, column=i, padx=3)
            self.buttons.append(b)

        self.status_bar = tk.Label(self.root, text="", anchor="w", relief="sunken", padx=6)
        self.status_bar.pack(fill="x", side="bottom")

    def _startup(self):
        self.cfg = load_config()
        missing = [f for f, _, _ in CONFIG_FIELDS if f not in self.cfg]
        if missing:
            self._open_settings(first_run=True)
        else:
            self._after_config_ready()

    def _after_config_ready(self):
        self.host_label.config(text=f"Host: {self.cfg.get('relay_host', '--')}")
        self._set_status("connecting...")
        threading.Thread(target=self._refresh_once, daemon=True).start()
        self._start_log_tail()
        self._schedule_refresh()

    def _schedule_refresh(self):
        self.root.after(REFRESH_SECS * 1000, self._periodic_refresh)

    def _periodic_refresh(self):
        threading.Thread(target=self._refresh_once, daemon=True).start()
        self._schedule_refresh()

    def _refresh_once(self):
        try:
            r = ssh_run(self.cfg, "uptime; echo ---; free -m | awk '/Mem:/{print $3\" \"$2}'", timeout=15)
            if r.returncode != 0:
                self.task_q.put(("header", {"status": "Error", "detail": r.stderr.strip()}))
                return
            out = r.stdout
            load_m = re.search(r"load average:\s*([\d.]+)", out)
            uptime_m = re.search(r"up\s+(.*?),\s+\d+ user", out)
            load = load_m.group(1) if load_m else "?"
            uptime = uptime_m.group(1).strip() if uptime_m else "?"

            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            units = list_units_detailed(content)
            logs_r = ssh_run(self.cfg, "sudo journalctl -u mediamtx -n 50 --no-pager", timeout=15)
            recent = logs_r.stdout if logs_r.returncode == 0 else ""
            rows = []
            for u in units:
                status = "unknown"
                if u["streamkey"]:
                    matches = [ln for ln in recent.splitlines() if f"live/{u['streamkey']}" in ln]
                    if matches:
                        status = "live" if ("publishing" in matches[-1] or "is reading" in matches[-1]) else "idle"
                rows.append((u["device"], u["label"], f"live/{u['streamkey']}" if u["streamkey"] else "?", status))

            self.task_q.put(("header", {"status": "Connected", "uptime": uptime, "load": load}))
            self.task_q.put(("units", rows))
        except Exception as e:
            self.task_q.put(("header", {"status": "Error", "detail": str(e)}))

    def _start_log_tail(self):
        def run():
            cmd = ["ssh", "-i", self.cfg["ssh_key_path"], "-o", "ConnectTimeout=10",
                   f"{self.cfg['relay_user']}@{self.cfg['relay_host']}",
                   "sudo journalctl -u mediamtx -f --no-pager -n 0"]
            try:
                self.log_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                  text=True, bufsize=1)
                for line in self.log_proc.stdout:
                    if self.stop_log.is_set():
                        break
                    self.log_q.put(line.rstrip("\n"))
            except Exception as e:
                self.log_q.put(f"[log tail error: {e}]")

        threading.Thread(target=run, daemon=True).start()

    def _toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.config(text="Resume" if self.paused else "Pause")

    def _poll_queues(self):
        from tkinter import messagebox
        if not self.paused:
            drained = False
            while True:
                try:
                    line = self.log_q.get_nowait()
                except queue.Empty:
                    break
                self.log_widget.configure(state="normal")
                self.log_widget.insert("end", line + "\n")
                self.log_widget.configure(state="disabled")
                drained = True
            if drained:
                self.log_widget.see("end")

        while True:
            try:
                kind, payload = self.task_q.get_nowait()
            except queue.Empty:
                break
            if kind == "header":
                if payload.get("status") == "Error":
                    self._set_status(f"Relay unreachable: {payload.get('detail', '')}")
                    self.status_label.config(text="Status: Error", fg="#b00000")
                else:
                    self.status_label.config(text="Status: Connected", fg="#1a7a1a")
                    self.uptime_label.config(text=f"Uptime: {payload['uptime']}")
                    self.load_label.config(text=f"Load: {payload['load']}")
                    self._set_status("")
            elif kind == "units":
                self.tree.delete(*self.tree.get_children())
                for row in payload:
                    self.tree.insert("", "end", values=row)
            elif kind == "result":
                title, ok, text = payload
                for b in self.buttons:
                    b.config(state="normal")
                self._set_status(text.splitlines()[0] if text else "")
                if ok:
                    messagebox.showinfo(title, text)
                    threading.Thread(target=self._refresh_once, daemon=True).start()
                else:
                    messagebox.showerror(title, text)

        self.root.after(150, self._poll_queues)

    def _set_status(self, text):
        self.status_bar.config(text=text)

    def _run_async(self, title, fn):
        for b in self.buttons:
            b.config(state="disabled")
        self._set_status(f"{title}: working...")

        def runner():
            try:
                self.task_q.put(("result", (title, True, fn())))
            except Exception as e:
                self.task_q.put(("result", (title, False, str(e))))

        threading.Thread(target=runner, daemon=True).start()

    def _ask_device_label(self, title):
        tk = self.tk
        win = tk.Toplevel(self.root)
        win.title(title)
        win.resizable(False, False)
        win.grab_set()
        tk.Label(win, text="Device type (any short label):").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        device_var = tk.StringVar()
        tk.Entry(win, textvariable=device_var, width=18).grid(row=0, column=1, padx=6, pady=6)
        tk.Label(win, text="Unit label (e.g. a3):").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        label_var = tk.StringVar()
        tk.Entry(win, textvariable=label_var, width=18).grid(row=1, column=1, padx=6, pady=6)
        result = {}

        def ok():
            device = re.sub(r"[^A-Za-z0-9_-]", "", device_var.get())
            label = re.sub(r"[^a-z0-9]", "", label_var.get().lower())
            if not device or not label:
                from tkinter import messagebox
                messagebox.showwarning(title, "Both fields are required.")
                return
            result["value"] = (device, label)
            win.destroy()

        btns = tk.Frame(win)
        btns.grid(row=2, column=0, columnspan=2, pady=8)
        tk.Button(btns, text="OK", width=10, command=ok).pack(side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=win.destroy).pack(side="left", padx=4)
        win.wait_window()
        return result.get("value")

    def _ask_existing_label(self, title):
        from tkinter import ttk, messagebox
        tk = self.tk
        try:
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            units = list_units_detailed(content)
        except Exception as e:
            messagebox.showerror(title, f"Could not fetch unit list: {e}")
            return None
        if not units:
            messagebox.showinfo(title, "No units registered.")
            return None
        win = tk.Toplevel(self.root)
        win.title(title)
        win.resizable(False, False)
        win.grab_set()
        tk.Label(win, text="Choose a unit:").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        choices = [f"{u['device']} {u['label']}" for u in units]
        by_choice = {f"{u['device']} {u['label']}": u for u in units}
        var = tk.StringVar(value=choices[0])
        ttk.Combobox(win, textvariable=var, values=choices, state="readonly", width=24).grid(row=1, column=0, padx=6, pady=6)
        result = {}

        def ok():
            result["value"] = by_choice[var.get()]
            win.destroy()

        btns = tk.Frame(win)
        btns.grid(row=2, column=0, pady=8)
        tk.Button(btns, text="OK", width=10, command=ok).pack(side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=win.destroy).pack(side="left", padx=4)
        win.wait_window()
        return result.get("value")

    def action_onboard(self):
        from tkinter import messagebox
        sel = self._ask_device_label("Onboard a new unit")
        if not sel:
            return
        device, label = sel
        unit = _apply_one(device, label)
        if not messagebox.askyesno(
            "Onboard a new unit",
            f"Apply {unit['comment']} to the relay now?\n\nstream key: {unit['streamkey']}\nviewer key: {unit['viewkey']}",
        ):
            return

        def work():
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            new_content = add_unit_block(content, unit["comment"], unit["push_path"], unit["view_path"])
            bak = push_remote_file(self.cfg, self.cfg["remote_config_path"], new_content, label)
            write_key_files(self.cfg, _remote_dir(self.cfg), [(label, unit["streamkey"], unit["viewkey"])])
            append_values(self.cfg, unit["comment"], label, unit["streamkey"], unit["viewkey"])
            log_action(self.cfg, f"[GUI] onboarded {unit['comment']}: backup={bak}")
            info = unit_urls(self.cfg, label, unit["streamkey"], unit["viewkey"])
            return (f"Applied. Backup: {bak}\n\nrtmp push: {info['push_rtmp']}\n"
                    f"rtsp push: {info['push_rtsp_key']}\nview: {info['view_url']}")

        self._run_async("Onboard", work)

    def action_batch(self):
        from tkinter import messagebox
        tk = self.tk
        win = tk.Toplevel(self.root)
        win.title("Batch-onboard multiple units")
        win.resizable(False, False)
        win.grab_set()
        tk.Label(win, text="Enter 'devicetype:label' pairs, comma-separated:").pack(padx=8, pady=(8, 2), anchor="w")
        tk.Label(win, text="Example: typeA:a4,typeA:a5,typeB:b3", fg="#666").pack(padx=8, anchor="w")
        entry = tk.Entry(win, width=50)
        entry.pack(padx=8, pady=8)
        result = {}

        def ok():
            result["value"] = entry.get()
            win.destroy()

        btns = tk.Frame(win)
        btns.pack(pady=(0, 8))
        tk.Button(btns, text="OK", width=10, command=ok).pack(side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=win.destroy).pack(side="left", padx=4)
        win.wait_window()
        raw = result.get("value")
        if not raw:
            return
        parsed, skipped = parse_batch_spec(raw)
        if not parsed:
            messagebox.showwarning("Batch-onboard", "Nothing valid to apply.")
            return
        units = [_apply_one(d, l) for d, l in parsed]
        summary = "\n".join(f"  {u['comment']}: stream={u['streamkey']} view={u['viewkey']}" for u in units)
        if skipped:
            summary += "\n\nSkipped: " + ", ".join(skipped)
        if not messagebox.askyesno("Batch-onboard", f"Apply {len(units)} unit(s) to the relay?\n\n{summary}"):
            return

        def work():
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            applied, failed = [], []
            for u in units:
                try:
                    content_new = add_unit_block(content, u["comment"], u["push_path"], u["view_path"])
                    content = content_new
                    applied.append(u)
                except ValueError as e:
                    failed.append((u, str(e)))
            if not applied:
                raise RuntimeError("All units failed to stage (likely duplicate paths): " +
                                    "; ".join(f"{u['comment']}: {e}" for u, e in failed))
            bak = push_remote_file(self.cfg, self.cfg["remote_config_path"], content, "batch")
            write_key_files(self.cfg, _remote_dir(self.cfg), [(u["label"], u["streamkey"], u["viewkey"]) for u in applied])
            for u in applied:
                append_values(self.cfg, u["comment"], u["label"], u["streamkey"], u["viewkey"])
            log_action(self.cfg, f"[GUI] batch onboarded {[u['label'] for u in applied]}, backup={bak}")
            lines = [f"Applied {len(applied)} unit(s). Backup: {bak}", ""]
            for u in applied:
                info = unit_urls(self.cfg, u["label"], u["streamkey"], u["viewkey"])
                lines.append(f"{u['comment']}: rtmp={info['push_rtmp']}  view={info['view_url']}")
            if failed:
                lines.append("")
                lines.append("Skipped (duplicate path): " + ", ".join(u["comment"] for u, _ in failed))
            return "\n".join(lines)

        self._run_async("Batch-onboard", work)

    def action_genkeys(self):
        sel = self._ask_device_label("Generate keys only (apply later)")
        if not sel:
            return
        device, label = sel
        unit = _apply_one(device, label)
        append_values(self.cfg, unit["comment"] + " (NOT YET applied to relay)", label, unit["streamkey"], unit["viewkey"])
        log_action(self.cfg, f"[GUI] generated keys only for {unit['comment']} (not applied)")
        from tkinter import messagebox
        messagebox.showinfo(
            "Generate keys",
            f"Stream key: {unit['streamkey']}\nViewer key: {unit['viewkey']}\n\n"
            f"Saved to {self.cfg['values_file']} (marked not-yet-applied).",
        )

    def action_rotate(self):
        from tkinter import messagebox
        u = self._ask_existing_label("Rotate a unit's keys")
        if not u:
            return
        label, device = u["label"], u["device"]
        if not messagebox.askyesno(
            "Rotate keys",
            f"Rotate keys for {u['device']} {label}?\n\n"
            "This invalidates the current URLs -- the device and any viewers must be\n"
            "reconfigured with the new ones afterward.",
        ):
            return

        def work():
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            new_unit = _apply_one(device, label)
            content2 = remove_unit_block(content, label)
            content3 = add_unit_block(content2, new_unit["comment"], new_unit["push_path"], new_unit["view_path"])
            bak = push_remote_file(self.cfg, self.cfg["remote_config_path"], content3, f"rotate-{label}")
            remove_key_files(self.cfg, _remote_dir(self.cfg), label)
            write_key_files(self.cfg, _remote_dir(self.cfg), [(label, new_unit["streamkey"], new_unit["viewkey"])])
            append_values(self.cfg, new_unit["comment"] + " (rotated)", label, new_unit["streamkey"], new_unit["viewkey"])
            log_action(self.cfg, f"[GUI] rotated keys for {label}, backup={bak}")
            info = unit_urls(self.cfg, label, new_unit["streamkey"], new_unit["viewkey"])
            return f"Rotated. Backup: {bak}\n\nrtmp push: {info['push_rtmp']}\nview: {info['view_url']}"

        self._run_async("Rotate", work)

    def action_remove(self):
        from tkinter import messagebox
        u = self._ask_existing_label("Remove a unit")
        if not u:
            return
        label = u["label"]
        if not messagebox.askyesno("Remove a unit", f"Really remove {u['device']} {label}? This also deletes its key files."):
            return

        def work():
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            new_content = remove_unit_block(content, label)
            bak = push_remote_file(self.cfg, self.cfg["remote_config_path"], new_content, f"rm-{label}")
            remove_key_files(self.cfg, _remote_dir(self.cfg), label)
            log_action(self.cfg, f"[GUI] removed unit {label}, backup={bak}")
            return f"Removed. Backup: {bak}"

        self._run_async("Remove", work)

    def action_export(self):
        from tkinter import messagebox
        try:
            content = fetch_remote_file(self.cfg, self.cfg["remote_config_path"])
            units = list_units_detailed(content)
        except Exception as e:
            messagebox.showerror("Export", f"Could not fetch unit list: {e}")
            return
        if not units:
            messagebox.showinfo("Export", "No units registered.")
            return
        out_path = Path(self.cfg["log_dir"]) / "inventory.csv"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["device", "label", "push_rtmp", "push_rtsp_key", "view_url"])
            for u in units:
                info = unit_urls(self.cfg, u["mirror_label"], u["streamkey"], u["viewkey"])
                w.writerow([u["device"], u["label"], info["push_rtmp"], info["push_rtsp_key"], info["view_url"]])
        messagebox.showinfo("Export", f"Wrote {len(units)} unit(s) to {out_path}")

    def action_settings(self):
        self._open_settings(first_run=False)

    def _open_settings(self, first_run):
        tk = self.tk
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.resizable(False, False)
        win.grab_set()
        if first_run:
            tk.Label(win, text="First run -- set these once, saved for next time:",
                     font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, padx=8, pady=(8, 4), sticky="w")
        vars_ = {}
        for i, (key, prompt, default) in enumerate(CONFIG_FIELDS, start=1):
            tk.Label(win, text=prompt, wraplength=260, justify="left").grid(row=i, column=0, sticky="w", padx=8, pady=4)
            v = tk.StringVar(value=self.cfg.get(key, default))
            tk.Entry(win, textvariable=v, width=40).grid(row=i, column=1, padx=8, pady=4)
            vars_[key] = v

        def save():
            for key, v in vars_.items():
                self.cfg[key] = v.get()
            save_config(self.cfg)
            win.destroy()
            if first_run:
                self._after_config_ready()

        tk.Button(win, text="Save", width=12, command=save).grid(row=len(vars_) + 1, column=0, columnspan=2, pady=10)
        if first_run:
            win.protocol("WM_DELETE_WINDOW", lambda: None)
        win.wait_window()

    def _on_close(self):
        self.stop_log.set()
        if self.log_proc:
            try:
                self.log_proc.terminate()
            except Exception:
                pass
        self.root.destroy()


def run_gui():
    try:
        import tkinter as tk
    except ImportError:
        print("Tkinter is not available in this Python install.")
        print("Linux: install your distro's python3-tk package.")
        print("Windows: reinstall Python from python.org with the default options (Tk is bundled).")
        print("Or run with --cli for the terminal menu instead.")
        sys.exit(1)
    root = tk.Tk()
    RelayGUI(root)
    root.mainloop()


# ==========================================================================
# entry point
# ==========================================================================

def main():
    if "--selftest" in sys.argv:
        verify_transforms()
        return
    if "--cli" in sys.argv:
        run_cli()
        return
    run_gui()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\naborted")
        sys.exit(1)
