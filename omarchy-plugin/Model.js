// Pure helpers shared by Service.qml, BarWidget.qml and Panel.qml — no
// Quickshell-only APIs here, so this stays trivially testable outside QML.

function pollSeconds(label) {
  switch (label) {
    case "1 second": return 1
    case "2 seconds": return 2
    case "5 seconds": return 5
    case "10 seconds": return 10
    default: return 2
  }
}

function emptyStatus() {
  return {
    running: false, iface: "", source: "", real_capture: false,
    fallback_reason: "", started: "", filter: "", captured: 0,
    kernel_drops: 0, bytes: 0, buffered: 0, displayed: 0, evicted: 0,
    ring_size: 0, capture_file: "", offline: false
  }
}

// BeeEye-gui's GET /api/status body — see internal/gui/session.go Status.
function parseStatus(raw) {
  if (!raw) return null
  try {
    var obj = JSON.parse(raw)
    return (obj && typeof obj === "object") ? obj : null
  } catch (e) {
    return null
  }
}

// BeeEye-gui's GET /api/packets body — a list of `summary` (session.go/server.go).
function parsePackets(raw) {
  try {
    var arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr : []
  } catch (e) {
    return []
  }
}

function formatBytes(n) {
  n = Number(n) || 0
  var units = ["B", "KB", "MB", "GB", "TB"]
  var i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i]
}

function formatCount(n) {
  n = Number(n) || 0
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "m"
  if (n >= 1000) return (n / 1000).toFixed(1) + "k"
  return String(n)
}

// "normal" (capturing real traffic), "warning" (running but no real capture
// pipeline — permissions, most likely), "stopped", or "unknown" (no status yet).
function statusSeverity(status) {
  if (!status) return "unknown"
  if (!status.running) return "stopped"
  if (!status.real_capture) return "warning"
  return "normal"
}

function statusLabel(status) {
  if (!status) return "BeeEye …"
  if (!status.running) return "BeeEye idle"
  var what = status.offline ? "replay" : (status.iface || status.source || "live")
  return "🐝 " + formatCount(status.captured) + " · " + what
}

function statusTooltip(status) {
  if (!status) return "Waiting for the BeeEye analyzer…"
  var lines = []
  lines.push(status.running
    ? "Capturing on " + (status.iface || status.source || "?")
    : "Capture stopped")
  if (status.running && !status.real_capture) {
    lines.push("No real capture pipeline: " + (status.fallback_reason || "check permissions"))
  }
  lines.push(formatCount(status.captured) + " packets · " + formatBytes(status.bytes))
  if (status.kernel_drops) lines.push(status.kernel_drops + " dropped by the kernel")
  if (status.filter) lines.push("filter: " + status.filter)
  return lines.join("\n")
}

function endpointLabel(p, side) {
  if (!p) return "?"
  var name = side === "src" ? p.src_name : p.dst_name
  var addr = side === "src" ? p.src : p.dst
  return name || addr || "?"
}

function packetLine(p) {
  if (!p) return ""
  return endpointLabel(p, "src") + " → " + endpointLabel(p, "dst")
}

function packetMeta(p) {
  if (!p) return ""
  var bits = [p.proto || "?", (p.length || 0) + "B"]
  if (p.info) bits.push(p.info)
  return bits.join(" · ")
}

function connectErrorText(url) {
  return "Can't reach " + url + " — is BeeEye-gui running there?"
}
