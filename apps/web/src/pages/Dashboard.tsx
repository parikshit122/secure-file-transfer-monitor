import React, { useEffect, useState } from 'react';
import { 
  RiShieldFlashLine, 
  RiAlertLine, 
  RiSafe2Line, 
  RiExchangeLine, 
  RiCheckDoubleLine,
  RiErrorWarningLine,
  RiTimeLine,
  RiRefreshLine,
  RiArrowRightSLine
} from 'react-icons/ri';
import { Link } from 'react-router-dom';
import '../styles/dashboard.css';

interface DashboardStats {
  total_transfers: number;
  total_threats: number;
  unresolved_alerts: number;
  quarantined_count: number;
  recent_alerts: Array<{
    id: number;
    severity: string;
    title: string;
    description: string;
    file_path: string | null;
    status: string;
    timestamp: string;
  }>;
}

interface FileEvent {
  id: number;
  event_type: string;
  source_path: string | null;
  dest_path: string | null;
  file_size: number;
  process_name: string;
  username: string;
  file_hash: string;
  integrity_state: string;
  timestamp: string;
}

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentEvents, setRecentEvents] = useState<FileEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, eventsRes] = await Promise.all([
        fetch('http://localhost:8000/api/stats'),
        fetch('http://localhost:8000/api/events?limit=8')
      ]);

      if (!statsRes.ok || !eventsRes.ok) {
        throw new Error('Failed to fetch stats from backend server.');
      }

      const statsData = (await statsRes.json()) as DashboardStats;
      const eventsData = (await eventsRes.json()) as FileEvent[];

      setStats(statsData);
      setRecentEvents(eventsData);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Backend connection error';
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatPath = (pathStr: string | null | undefined): string => {
    if (!pathStr) return 'N/A';
    return pathStr.replace(/\\/g, '/');
  };

  const formatTimestamp = (ts: string | null | undefined): string => {
    if (!ts) return 'Just now';
    try {
      const cleanTs = ts.includes('Z') ? ts : `${ts}Z`;
      const date = new Date(cleanTs);
      return isNaN(date.getTime()) ? ts : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return String(ts);
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div>
          <h2>System Command Center</h2>
          <p>Real-Time Secure File Transfer & Active Defense Monitor</p>
        </div>
        <button className="btn-secondary refresh-btn" onClick={fetchDashboardData} disabled={loading}>
          <RiRefreshLine className={loading ? 'spin' : ''} /> Refresh Data
        </button>
      </header>

      {error && (
        <div className="dashboard-error-banner glass-card">
          <RiErrorWarningLine className="error-icon" />
          <span>System Alert: {error}. Check if backend server is running on port 8000.</span>
        </div>
      )}

      {/* Metrics Cards Grid */}
      <div className="stats-grid">
        <div className="stat-card glass-card">
          <div className="stat-icon icon-cyan">
            <RiExchangeLine />
          </div>
          <div className="stat-info">
            <span className="stat-label">Total File Transfers</span>
            <h3 className="stat-value">{stats?.total_transfers ?? 0}</h3>
            <span className="stat-sub">Logged Watchdog Events</span>
          </div>
        </div>

        <div className="stat-card glass-card">
          <div className="stat-icon icon-amber">
            <RiShieldFlashLine />
          </div>
          <div className="stat-info">
            <span className="stat-label">Threats Scanned</span>
            <h3 className="stat-value">{stats?.total_threats ?? 0}</h3>
            <span className="stat-sub">Score ≥ 35 Detected</span>
          </div>
        </div>

        <div className="stat-card glass-card">
          <div className="stat-icon icon-rose">
            <RiAlertLine />
          </div>
          <div className="stat-info">
            <span className="stat-label">Unresolved Alerts</span>
            <h3 className="stat-value">{stats?.unresolved_alerts ?? 0}</h3>
            <span className="stat-sub">Requires Review</span>
          </div>
        </div>

        <div className="stat-card glass-card">
          <div className="stat-icon icon-purple">
            <RiSafe2Line />
          </div>
          <div className="stat-info">
            <span className="stat-label">Quarantined Vault</span>
            <h3 className="stat-value">{stats?.quarantined_count ?? 0}</h3>
            <span className="stat-sub">Auto-Isolated Files</span>
          </div>
        </div>
      </div>

      {/* Main Grid Section */}
      <div className="dashboard-main-grid">
        {/* Recent File Transfers Table */}
        <div className="dashboard-section glass-card events-section">
          <div className="section-header">
            <h3>Recent Transfers & Movements</h3>
            <Link to="/monitor" className="view-all-link">
              View All <RiArrowRightSLine />
            </Link>
          </div>

          <div className="table-wrapper">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Source File</th>
                  <th>Process</th>
                  <th>Integrity</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="empty-row">No file transfer events logged yet</td>
                  </tr>
                ) : (
                  recentEvents.map((event) => (
                    <tr key={event.id}>
                      <td>
                        <span className={`badge event-badge badge-${(event.event_type || 'create').toLowerCase()}`}>
                          {event.event_type || 'CREATE'}
                        </span>
                      </td>
                      <td className="path-cell" title={formatPath(event.source_path)}>
                        {formatPath(event.source_path).split('/').pop() || 'File'}
                      </td>
                      <td className="process-cell">{event.process_name || 'explorer.exe'}</td>
                      <td>
                        <span className={`badge integrity-badge badge-${(event.integrity_state || 'baseline').toLowerCase()}`}>
                          {event.integrity_state || 'BASELINE'}
                        </span>
                      </td>
                      <td className="time-cell">{formatTimestamp(event.timestamp)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Alerts Feed */}
        <div className="dashboard-section glass-card alerts-section">
          <div className="section-header">
            <h3>Active Security Alerts</h3>
            <Link to="/alerts" className="view-all-link">
              Alert Vault <RiArrowRightSLine />
            </Link>
          </div>

          <div className="alerts-feed">
            {(!stats?.recent_alerts || stats.recent_alerts.length === 0) ? (
              <div className="empty-alerts">
                <RiCheckDoubleLine className="clean-icon" />
                <p>All Systems Secure</p>
                <span>No unresolved threat alerts</span>
              </div>
            ) : (
              stats.recent_alerts.map((alert) => (
                <div key={alert.id} className={`alert-item severity-${(alert.severity || 'high').toLowerCase()}`}>
                  <div className="alert-header">
                    <span className="alert-title">{alert.title || 'Security Warning'}</span>
                    <span className="alert-time"><RiTimeLine /> {formatTimestamp(alert.timestamp)}</span>
                  </div>
                  <p className="alert-desc">{alert.description || 'Threat detected'}</p>
                  {alert.file_path && (
                    <span className="alert-path">{formatPath(alert.file_path)}</span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;