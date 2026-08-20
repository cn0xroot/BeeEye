import { Component } from 'react'

// ErrorBoundary keeps one broken pane from blanking the whole analyzer.
//
// A live capture is stateful: losing the page to a render error means losing
// the packets in the browser's buffer and, if the operator reloads, possibly
// the investigation. Containing the failure to its pane and printing what went
// wrong is strictly better than a white screen.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('BeeEye pane crashed:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <section className="pane">
          <div className="empty">
            <div className="empty-title">⚠ {this.props.label || 'Pane failed to render'}</div>
            <div className="empty-help">
              <code>{String(this.state.error.message || this.state.error)}</code>
            </div>
            <button className="btn btn-ghost tiny" onClick={() => this.setState({ error: null })}>
              retry
            </button>
          </div>
        </section>
      )
    }
    return this.props.children
  }
}
