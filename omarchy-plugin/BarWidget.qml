import QtQuick
import qs.Commons
import qs.Ui
import "Model.js" as Model

BarWidget {
  id: root
  moduleName: "dev.beeeye.live-analyzer"

  property var service: null

  function resolveService() {
    if (root.service || !root.bar || !root.bar.shell) return
    if (typeof root.bar.shell.serviceFor !== "function") return
    var candidate = root.bar.shell.serviceFor(root.moduleName)
    if (candidate) {
      root.service = candidate
      root.injectPanel()
    }
  }

  Timer {
    interval: 500
    running: root.service === null
    repeat: true
    triggeredOnStart: true
    onTriggered: root.resolveService()
  }

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
    if ("service" in target) target.service = root.service
  }

  onServiceChanged: injectPanel()
  onBarChanged: { root.resolveService(); root.injectPanel() }
  onSettingsChanged: root.injectPanel()

  function refresh() {
    if (root.service) {
      root.service.sampleStatus()
      root.service.samplePackets()
    }
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() {
    if (panelLoader.item && panelLoader.item.openFromHotkey) panelLoader.item.openFromHotkey()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  readonly property bool popoutSwitchClosing:
    panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  readonly property var status: root.service ? root.service.status : null
  readonly property bool reachable: root.service ? root.service.reachable === true : false
  readonly property string severity: root.reachable ? Model.statusSeverity(root.status) : "unknown"

  visible: true
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.reachable ? Model.statusLabel(root.status) : "🐝 BeeEye –"
    fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
    active: root.severity === "warning"
    tooltipText: root.reachable
      ? Model.statusTooltip(root.status)
      : (root.service ? root.service.lastError : "Waiting for the BeeEye analyzer…")
    Accessible.role: Accessible.Button
    Accessible.name: root.opened ? "Close BeeEye Live" : "Open BeeEye Live"

    onPressed: function (mouseButton) {
      if (mouseButton === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }
  }
}
