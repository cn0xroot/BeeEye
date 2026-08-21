import { Component } from 'react'

// ErrorBoundary keeps one broken view from taking down navigation with it.
//
// Without this, a render error in whichever view is on screen (Overview,
// Alerts, …) unmounts the entire React tree — including the nav bar sitting
// right next to it — leaving a blank page where even clicking a different
// tab does nothing, because the DOM nodes those click handlers were on are
// gone. Containing the failure to the content area and printing what went
// wrong is strictly better than that.
//
// App.jsx re-keys this per `view` (key={view}) so switching tabs mounts a
// fresh boundary instead of one still stuck showing a previous view's error.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('BeeEye view crashed:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="view">
          <section className="card wide">
            <div className="empty">
              <div className="empty-title">⚠ {this.props.label || 'This view failed to render'}</div>
              <div className="empty-help">
                <code>{String(this.state.error.message || this.state.error)}</code>
              </div>
              <button className="btn ghost tiny" onClick={() => this.setState({ error: null })}>
                retry
              </button>
            </div>
          </section>
        </div>
      )
    }
    return this.props.children
  }
}
