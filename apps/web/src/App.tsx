import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import FileMonitor from "./pages/FileMonitor";
import Scanner from "./pages/Scanner";
import Alerts from "./pages/Alerts";
import Policies from "./pages/Policies";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/monitor" element={<FileMonitor />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
