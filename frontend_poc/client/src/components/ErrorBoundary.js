import React from "react";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep diagnostic information available without taking down the application.
    console.error("Report rendering failed:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <section className="bg-white border border-red-200 rounded-lg p-6 text-red-800" role="alert">
          <h2 className="text-xl font-semibold">Unable to render this report section</h2>
          <p className="mt-2 text-sm">{this.props.message || "The analysis completed, but part of its response was incomplete."}</p>
          <button className="mt-4 px-3 py-2 rounded bg-red-700 text-white" onClick={() => this.setState({ error: null })}>
            Retry rendering
          </button>
        </section>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
