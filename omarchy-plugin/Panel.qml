import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "dev.beeeye.live-analyzer"
  ipcTarget: "dev.beeeye.live-analyzer"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root
  property var service: null
  property int revision: 0

  readonly property var status: {
    root.revision
    return root.service ? root.service.status : Model.emptyStatus()
  }
  readonly property var packets: {
    root.revision
    return root.service ? root.service.packets : []
  }
  readonly property bool reachable: {
    root.revision
    return root.service ? root.service.reachable === true : false
  }
  readonly property string lastError: {
    root.revision
    return root.service ? String(root.service.lastError || "") : "service unavailable"
  }
  readonly property string baseUrl: {
    root.revision
    return root.service ? root.service.baseUrl : "http://localhost:8081"
  }

  readonly property string severity: root.reachable ? Model.statusSeverity(root.status) : "unknown"
  readonly property string label: root.reachable ? Model.statusLabel(root.status) : "BeeEye Live"
  readonly property string tooltip: root.reachable ? Model.statusTooltip(root.status) : root.lastError
  readonly property bool isAlert: root.severity === "warning"

  function levelColor(level) {
    if (level === "warning") return Qt.hsla(0.11, 0.72, 0.58, 1.0)
    if (level === "stopped" || level === "unknown") return root.bar ? Qt.darker(root.bar.foreground, 1.3) : Color.muted
    return Qt.hsla(0.33, 0.55, 0.5, 1.0) // normal / real capture running
  }

  function refresh() {
    if (root.service) {
      root.service.sampleStatus()
      root.service.samplePackets()
    }
  }

  function openAnalyzer() {
    if (root.service) root.service.openAnalyzer()
  }

  function open() {
    root.controller.show()
    root.refresh()
  }

  function openFromHotkey() {
    root.controller.show()
    root.refresh()
  }

  function close() { root.controller.hide() }
  function toggle() { if (root.opened) root.close(); else root.openFromHotkey() }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  Connections {
    target: root.service
    ignoreUnknownSignals: true
    function onStatusChanged() { root.revision++ }
    function onPacketsChanged() { root.revision++ }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.openFromHotkey() }
    function close(): void { root.close() }
    function show(): void { root.openFromHotkey() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.refresh() }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: true
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(contentColumn.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function (direction) { root.switchPanel(direction) }
      onTextKey: function (key) {
        if (key === "r") root.refresh()
        else if (key === "o") root.openAnalyzer()
      }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: contentColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: contentColumn
          width: parent.width
          spacing: Style.space(10)

          Column {
            anchors.left: parent.left
            anchors.leftMargin: Style.space(16)
            anchors.right: parent.right
            anchors.rightMargin: Style.space(16)
            spacing: Style.space(3)

            Text {
              text: "BEEEYE LIVE ANALYZER"
              textFormat: Text.PlainText
              width: parent.width
              elide: Text.ElideRight
              color: root.levelColor(root.severity)
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.title
              font.bold: true
              font.letterSpacing: 1
            }

            Text {
              text: root.reachable
                ? (root.status.running
                    ? "Capturing on " + (root.status.iface || root.status.source || "?")
                      + (root.status.offline ? " (replaying a capture file)" : "")
                    : "Capture stopped")
                : root.lastError
              textFormat: Text.PlainText
              width: parent.width
              wrapMode: Text.WordWrap
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.body
            }

            Text {
              visible: root.reachable && root.status.running && !root.status.real_capture
              text: "No real capture pipeline: " + (root.status.fallback_reason || "check permissions")
              textFormat: Text.PlainText
              width: parent.width
              wrapMode: Text.WordWrap
              color: root.levelColor("warning")
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              visible: root.reachable
              text: root.baseUrl
              textFormat: Text.PlainText
              width: parent.width
              elide: Text.ElideRight
              color: root.bar ? Qt.darker(root.bar.foreground, 1.4) : Color.muted
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          PanelSeparator { foreground: root.bar ? root.bar.foreground : Color.foreground }

          PanelSectionHeader {
            text: "COUNTERS"
            leftPadding: Style.space(16)
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Row {
            anchors.left: parent.left
            anchors.leftMargin: Style.space(16)
            anchors.right: parent.right
            anchors.rightMargin: Style.space(16)
            spacing: Style.space(16)

            Repeater {
              model: root.reachable ? [
                { label: "packets", value: Model.formatCount(root.status.captured) },
                { label: "bytes", value: Model.formatBytes(root.status.bytes) },
                { label: "kernel drops", value: String(root.status.kernel_drops || 0) },
                { label: "buffered", value: root.status.buffered + " / " + root.status.ring_size }
              ] : []

              Column {
                required property var modelData
                spacing: Style.space(2)
                Text {
                  text: modelData.value
                  textFormat: Text.PlainText
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.body
                  font.bold: true
                }
                Text {
                  text: modelData.label
                  textFormat: Text.PlainText
                  color: root.bar ? Qt.darker(root.bar.foreground, 1.4) : Color.muted
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                }
              }
            }
          }

          PanelSeparator { foreground: root.bar ? root.bar.foreground : Color.foreground }

          PanelSectionHeader {
            text: "RECENT PACKETS"
            leftPadding: Style.space(16)
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Text {
            visible: root.reachable && root.packets.length === 0
            anchors.left: parent.left
            anchors.leftMargin: Style.space(16)
            anchors.right: parent.right
            anchors.rightMargin: Style.space(16)
            text: root.status.running ? "Waiting for packets…" : "Capture is stopped — nothing to show"
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            color: root.bar ? Qt.darker(root.bar.foreground, 1.4) : Color.muted
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
            font.pixelSize: Style.font.bodySmall
          }

          Column {
            anchors.left: parent.left
            anchors.leftMargin: Style.space(16)
            anchors.right: parent.right
            anchors.rightMargin: Style.space(16)
            spacing: Style.space(4)

            Repeater {
              model: root.reachable ? root.packets : []

              Column {
                required property var modelData
                width: parent.width
                spacing: Style.space(1)

                Text {
                  text: Model.packetLine(modelData)
                  textFormat: Text.PlainText
                  width: parent.width
                  elide: Text.ElideRight
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.bodySmall
                }
                Text {
                  text: Model.packetMeta(modelData)
                  textFormat: Text.PlainText
                  width: parent.width
                  elide: Text.ElideRight
                  color: root.bar ? Qt.darker(root.bar.foreground, 1.4) : Color.muted
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                }
              }
            }
          }

          PanelSeparator { foreground: root.bar ? root.bar.foreground : Color.foreground }

          Column {
            anchors.left: parent.left
            anchors.leftMargin: Style.space(16)
            anchors.right: parent.right
            anchors.rightMargin: Style.space(16)
            spacing: Style.space(3)

            Text {
              text: "This mirrors BeeEye-gui — it polls its HTTP API and shows nothing that page doesn't. Starting/stopping capture and deep packet inspection stay there."
              textFormat: Text.PlainText
              width: parent.width
              wrapMode: Text.WordWrap
              color: root.bar ? Qt.darker(root.bar.foreground, 1.3) : Color.muted
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              text: "r refresh · o open full analyzer · Esc close"
              textFormat: Text.PlainText
              width: parent.width
              wrapMode: Text.WordWrap
              color: root.bar ? Qt.darker(root.bar.foreground, 1.45) : Color.muted
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Item { width: 1; height: Style.space(4) }
        }
      }
    }
  }
}
