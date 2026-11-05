import { useQuery } from '@tanstack/react-query'

async function fetchStats() {
  const res = await fetch('/api/stats')
  return res.json()
}

async function fetchEvents() {
  const res = await fetch('/api/events')
  return res.json()
}

export default function Dashboard() {
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 3000 })
  const events = useQuery({ queryKey: ['events'], queryFn: fetchEvents, refetchInterval: 5000 })

  const s = stats.data || { files_monitored: 0, threats_blocked: 0, active_alerts: 0, integrity_checks: 0 }

  const cards = [
    { label: 'Files Monitored', value: s.files_monitored, color: 'text-blue-400' },
    { label: 'Threats Blocked', value: s.threats_blocked, color: 'text-red-400' },
    { label: 'Active Alerts', value: s.active_alerts, color: 'text-yellow-400' },
    { label: 'Integrity Checks', value: s.integrity_checks, color: 'text-emerald-400' },
  ]

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Security Dashboard</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {cards.map((stat) => (
          <div key={stat.label} className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <p className="text-sm text-gray-500">{stat.label}</p>
            <p className={"text-3xl font-bold mt-2 " + stat.color}>{stat.value}</p>
          </div>
        ))}
      </div>

      <h3 className="text-lg font-semibold mb-4">Recent Events</h3>
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-500">
              <th className="text-left p-4">Time</th>
              <th className="text-left p-4">Event</th>
              <th className="text-left p-4">File</th>
              <th className="text-left p-4">Type</th>
              <th className="text-left p-4">Status</th>
            </tr>
          </thead>
          <tbody>
            {events.data && events.data.length > 0 ? (
              events.data.map((e: any) => (
                <tr key={e.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="p-4 text-gray-400">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td className="p-4">
                    <span className={"px-2 py-1 rounded text-xs font-medium " + (
                      e.event_type === 'created' ? 'bg-blue-500/20 text-blue-400' :
                      e.event_type === 'deleted' ? 'bg-red-500/20 text-red-400' :
                      e.event_type === 'moved' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-gray-500/20 text-gray-400'
                    )}>
                      {e.event_type}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-gray-300">{e.file_name}</td>
                  <td className="p-4 text-gray-400">{e.file_type}</td>
                  <td className="p-4">
                    <span className={"px-2 py-1 rounded text-xs " + (
                      e.threat_level === 'clean' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                    )}>
                      {e.threat_level}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="p-8 text-center text-gray-600">
                  No events yet. Create a file in E:\SFTMS\test_watch to see live data.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
