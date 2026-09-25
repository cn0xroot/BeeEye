import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// Background owner for polling BeeEye-gui's HTTP API. It never touches a
// socket or the network stack itself — it shells out to curl, the same way
// the reference PSI plugin shells out to read /proc/pressure, so this stays
// a plain unprivileged HTTP client with a hard timeout and no retry storm.
Item {
  id: root

  property var shell: null
  property var manifest: null

  readonly property string moduleId: "dev.beeeye.live-analyzer"
  readonly property string home: Quickshell.env("HOME") || ""
  readonly property string configPath:
    (Quickshell.env("XDG_CONFIG_HOME") || home + "/.config") + "/omarchy/shell.json"

  property string baseUrl: "http://localhost:8081"
  property string pollInterval: "2 seconds"
  property int packetLimit: 12

  property var status: Model.emptyStatus()
  property var packets: []
  property bool reachable: false
  property string lastError: ""
  property bool settingsLoaded: false

  signal statusChanged()
  signal packetsChanged()

  function readSettings() {
    var conf
    try {
      conf = JSON.parse(configFile.text() || "")
    } catch (e) {
      root.settingsLoaded = true
      return
    }
    root.settingsLoaded = true
    if (!conf || !conf.bar || !conf.bar.layout) return
    var zones = ["left", "center", "right"]
    for (var z = 0; z < zones.length; z++) {
      var entries = conf.bar.layout[zones[z]] || []
      for (var i = 0; i < entries.length; i++) {
        var entry = entries[i]
        if (!entry || entry.id !== root.moduleId) continue
        if (typeof entry.baseUrl === "string" && entry.baseUrl.length > 0) {
          root.baseUrl = entry.baseUrl.replace(/\/+$/, "")
        }
        if (["1 second", "2 seconds", "5 seconds", "10 seconds"].indexOf(entry.pollInterval) >= 0) {
          root.pollInterval = entry.pollInterval
        }
        var limit = parseInt(entry.packetLimit, 10)
        if (!isNaN(limit)) root.packetLimit = Math.max(5, Math.min(30, limit))
        return
      }
    }
  }

  function sampleStatus() {
    statusProc.command = ["curl", "-s", "-m", "3", root.baseUrl + "/api/status"]
    statusProc.running = true
  }

  function samplePackets() {
    packetsProc.command = ["curl", "-s", "-m", "3",
      root.baseUrl + "/api/packets?limit=" + root.packetLimit]
    packetsProc.running = true
  }

  function acceptStatus(raw) {
    var parsed = Model.parseStatus(raw)
    if (!parsed) {
      root.reachable = false
      root.lastError = Model.connectErrorText(root.baseUrl)
      root.statusChanged()
      return
    }
    root.reachable = true
    root.lastError = ""
    root.status = parsed
    root.statusChanged()
  }

  function acceptPackets(raw) {
    var parsed = Model.parsePackets(raw)
    if (parsed.length > 0 || raw === "[]") root.packets = parsed
    root.packetsChanged()
  }

  // openAnalyzer/openFile intentionally stay out of scope: this plugin
  // mirrors the live analyzer, it does not re-implement its controls.
  function openAnalyzer() {
    openProc.command = ["xdg-open", root.baseUrl]
    openProc.running = true
  }

  Process {
    id: statusProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.acceptStatus(text)
    }
    onExited: function (code) {
      if (code !== 0) {
        root.reachable = false
        root.lastError = Model.connectErrorText(root.baseUrl)
        root.statusChanged()
      }
    }
  }

  Process {
    id: packetsProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.acceptPackets(text)
    }
  }

  Process {
    id: openProc
  }

  FileView {
    id: configFile
    path: root.configPath
    printErrors: false
    watchChanges: true
    onFileChanged: reload()
    onLoaded: root.readSettings()
    onLoadFailed: root.settingsLoaded = true
  }

  Timer {
    interval: Model.pollSeconds(root.pollInterval) * 1000
    running: root.settingsLoaded
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      root.sampleStatus()
      root.samplePackets()
    }
  }
}
