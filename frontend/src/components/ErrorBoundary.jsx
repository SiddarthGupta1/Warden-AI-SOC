import React from 'react';
import { AlertTriangle, RefreshCw, LogOut } from 'lucide-react';

/**
 * Catches render errors anywhere below it.
 *
 * Without a boundary, React unmounts the whole tree when any component throws,
 * which presents as a blank white page with no explanation — the failure mode is
 * indistinguishable from the server being down. Triage reports are model-generated
 * and their optional fields are not guaranteed, so a missing array is a realistic
 * cause rather than a theoretical one.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    // Keep the detail in the console for whoever is debugging.
    console.error('[ErrorBoundary] render failure:', error, info?.componentStack);
  }

  handleReload = () => {
    this.setState({ error: null, info: null });
    window.location.reload();
  };

  handleSignOut = () => {
    localStorage.removeItem('warden_token');
    localStorage.removeItem('warden_user');
    window.location.reload();
  };

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="min-h-screen bg-slate-100 dark:bg-[#070A11] flex items-center justify-center p-6">
        <div className="max-w-xl w-full bg-white dark:bg-slate-900 border border-amber-500/40 rounded-xl p-6 shadow-xl">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-6 h-6 text-amber-500 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <h1 className="text-base font-bold text-slate-900 dark:text-slate-100">
                The console hit a rendering error
              </h1>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Your data is safe — triage reports and the audit trail are stored server-side.
                This is a display fault in the browser only.
              </p>
            </div>
          </div>

          <pre className="mt-4 text-[11px] font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-red-600 dark:text-red-400 overflow-x-auto whitespace-pre-wrap">
            {String(this.state.error?.message || this.state.error)}
          </pre>

          {this.state.info?.componentStack && (
            <details className="mt-2">
              <summary className="text-[11px] text-slate-500 cursor-pointer select-none">
                Component stack
              </summary>
              <pre className="mt-2 text-[10px] font-mono text-slate-500 dark:text-slate-400 overflow-x-auto max-h-48">
                {this.state.info.componentStack}
              </pre>
            </details>
          )}

          <div className="mt-5 flex items-center space-x-2">
            <button
              onClick={this.handleReload}
              className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reload console</span>
            </button>
            <button
              onClick={this.handleSignOut}
              className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold hover:bg-slate-50 dark:hover:bg-slate-800"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign out and retry</span>
            </button>
          </div>

          <p className="mt-3 text-[10px] text-slate-400">
            If this repeats, the full error and component stack are in the browser console.
          </p>
        </div>
      </div>
    );
  }
}
