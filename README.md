# MediaMTX Relay Manager

A GUI and CLI for managing per-unit anonymous-publish access on a
[MediaMTX](https://github.com/bluenviron/mediamtx) relay, at scale.
Self-contained: pure Python standard library (Tkinter + `subprocess` + your
system's `ssh`), no `pip install`, one file. Runs on Linux and on old
Windows.

## The problem this solves

A fleet of RTMP/RTSP publishers that can't send a login — common on
embedded or IP-camera-style devices — can only be authorized by MediaMTX's
"anonymous publish, but only to one exact path" mechanism: give each unit a
random, unguessable path segment (its **stream key**), and configure
MediaMTX to allow anonymous publish on exactly that one path. A second
random segment (**viewer key**) gates a read-only mirror path so other
clients can watch without ever seeing the push key.

Hand-editing MediaMTX's `authInternalUsers`/`paths` YAML for every new unit
doesn't scale and is easy to get wrong — a boundary regex that swallows the
wrong entries corrupts every other unit's access at once. This tool
generates both keys, applies the YAML change safely (always backs up
first, validates the result afterward), and gives you a GUI (or a terminal
menu) for:

- Onboarding one unit, or a batch of units in a single relay round trip
- Pre-generating keys to apply later
- Rotating a unit's keys
- Removing a unit
- Listing registered units and exporting a CSV inventory
- Watching the relay's logs live

The tool makes no assumption about what kind of device is publishing —
"device type" is just a label you choose, used only in the config's
comments and the units table.

## Requirements

- Python 3.8+ with Tkinter (bundled with the default python.org Windows
  installer; on Debian/Ubuntu: `sudo apt install python3-tk`)
- An `ssh` client on `PATH` (Windows 10/11 ship one; on Windows 7, install
  any OpenSSH-compatible client, e.g. Git for Windows)
- SSH access to a host running MediaMTX, with `sudo` rights to read and
  write its config file

## Usage

```
python mediamtx_relay_manager.py            # GUI
python mediamtx_relay_manager.py --cli      # terminal menu
python mediamtx_relay_manager.py --selftest # verify the YAML transforms,
                                             # never touches a relay
```

First run asks for your SSH key path, relay host/user, the remote config
path (defaults to `/etc/mediamtx/mediamtx.yml`), and where to save a local
key inventory and an audit log. These are remembered in
`~/.mediamtx_relay_manager/config.json`.

## Design notes / why it's safe to point at a real relay

- Every write is preceded by a timestamped backup of the config file on the
  relay itself, and followed by a YAML-validity check before the change is
  considered applied.
- The core YAML transforms (`add_unit_block`, `remove_unit_block`,
  `list_units_detailed`) are pure functions with no side effects, covered
  by `verify_transforms()` (`--selftest`): an add-then-remove round trip
  must reproduce the original file byte-for-byte, sequential adds must not
  cross-contaminate each other, and a duplicate publish path must be
  rejected rather than silently double-registered.
- Before being trusted against a real deployment, this logic was also
  tested against a real fetched copy of a production `mediamtx.yml` (not
  shown here) — that caught three real bugs pre-deployment, including an
  insertion-order bug that would have caused a later `remove` to silently
  swallow every other unit's entry. The lesson generalizes: if you adapt
  this tool to a config layout that differs from the shape assumed here,
  re-run `--selftest` against your own fetched config before using the
  write paths live.

## What this tool does *not* do

- It doesn't manage MediaMTX itself (installation, TLS, the `publisher`/
  `viewer`-style catch-all logins) — only the per-unit anonymous-path
  entries.
- It doesn't manage the publishing device's own configuration — you still
  need to enter the generated stream key into your camera/encoder
  yourself, however its own config UI expects it.

## License

MIT — see [LICENSE](LICENSE).
