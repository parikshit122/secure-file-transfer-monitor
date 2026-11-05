import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'

const queryClient = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/events" element={<div className="text-gray-400">Live Events - Coming Soon</div>} />
            <Route path="/scans" element={<div className="text-gray-400">Scan Results - Coming Soon</div>} />
            <Route path="/alerts" element={<div className="text-gray-400">Alerts - Coming Soon</div>} />
            <Route path="/settings" element={<div className="text-gray-400">Settings - Coming Soon</div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
