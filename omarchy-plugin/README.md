# BeeEye Live — Omarchy plugin

Mirrors BeeEye's live analyzer (`BeeEye-gui`, the Wireshark-style capture UI
at `http://localhost:8081`) in the Omarchy (Quattro shell) bar: a status
pill with the packet/byte counters, plus a panel with kernel-drop counts and
a rolling feed of the most recent packets.

It is a **read-only mirror**. It polls BeeEye-gui's existing HTTP API
(`GET /api/status`, `GET /api/packets`) and renders what those endpoints
already return — it does not touch capture, filters, or packet internals.
Starting/stopping capture, the protocol field tree, and the hex dump stay in
the full analyzer, which the panel's "open full analyzer" action opens in
your browser.

## Requirements

- Omarchy Quattro shell with plugin support (`omarchy plugin …`).
- `curl` and `xdg-open` on `$PATH` (the plugin shells out to both — see
  [Why `curl` and not QML's HTTP client](#why-curl-and-not-qmls-http-client)).
- `BeeEye-agent/bin/BeeEye-gui` running and reachable at the configured URL
  (default `http://localhost:8081`). If your Hyprland/Omarchy desktop is not
  the same machine as the BeeEye gateway, point `baseUrl` at an address you
  can actually reach it on (LAN IP, SSH tunnel, etc.) — see [Settings](#settings).

## Files

```
manifest.json   plugin metadata, kinds, settings schema
Service.qml     headless singleton: polls BeeEye-gui, holds the last status/packets
BarWidget.qml   bar pill: capture state + packet count
Panel.qml       popover: counters, kernel drops, recent packets
Model.js        pure formatting/parsing helpers shared by the three QML files
```

`Service.qml` is the only thing that talks to BeeEye-gui; `BarWidget.qml`
and `Panel.qml` just read its `status`/`packets` properties, the same
service/bar-widget/panel split the built-in and marketplace plugins use.

## Settings

Configurable from the plugin's bar-widget settings (or by hand in
`~/.config/omarchy/shell.json`, under the widget's entry in `bar.layout`):

| Key | Default | Meaning |
|---|---|---|
| `baseUrl` | `http://localhost:8081` | Base URL of the BeeEye-gui live analyzer. |
| `pollInterval` | `2 seconds` | How often `/api/status` and `/api/packets` are polled. |
| `packetLimit` | `12` | How many recent packets the panel lists. |

## Try it locally

```bash
omarchy plugin validate .          # from this directory
omarchy plugin add . --enable      # or point at a git remote once published
```

Bar pill states:
- 🐝 *green label* — capturing real traffic (`running && real_capture`).
- 🐝 *amber/alert* — capture is "running" but with no real capture pipeline
  (missing `CAP_BPF`/`CAP_NET_RAW` — the same honest fallback BeeEye-gui
  itself reports, never a simulated trace; see the main repo's `README.md`,
  "Capturing real packets").
- `BeeEye idle` — capture stopped.
- `BeeEye –` — analyzer unreachable at `baseUrl` (not running, wrong URL,
  firewalled).

Keys inside the panel: `r` refresh, `o` open the full analyzer, `Esc` close.

## Why `curl` and not QML's HTTP client

Shelling out to `curl` with a hard `-m 3` timeout keeps `Service.qml` simple
and matches the pattern used by other Quattro-shell plugins that fetch
external data via `Quickshell.Io.Process` rather than QML's `XMLHttpRequest`
— predictable timeout/error handling, and no risk of a hung request blocking
the shell's JS engine.

## Publishing to plugins.omarchy.org

This folder is laid out so it can become (or be extracted to) the *root* of
its own public git repository, which the marketplace requires. Before
submitting: pick a real `license` in `manifest.json` (currently a
placeholder — match whatever license the main BeeEye repository ships
under), add a `preview.png`, and run `omarchy plugin validate` against the
final repo root.
