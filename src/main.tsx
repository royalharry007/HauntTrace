import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

/** If the UI ever breaks, say so instead of showing an empty window. */
class Boundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="speech" style={{ padding: 24 }}>
        <h1>The guardian tripped over something.</h1>
        <p className="dim">Monitoring keeps running in the background. Reload the window to continue.</p>
        <pre style={{ whiteSpace: "pre-wrap", fontSize: 14 }}>{String(this.state.error.stack ?? this.state.error)}</pre>
        <button className="px-btn primary" onClick={() => location.reload()}>Reload</button>
      </div>
    );
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Boundary>
      <App />
    </Boundary>
  </React.StrictMode>,
);
