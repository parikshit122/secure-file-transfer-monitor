import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import FileMonitor from "./pages/FileMonitor";
import Scanner from "./pages/Scanner";
import Alerts from "./pages/Alerts";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/monitor" element={<FileMonitor />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/alerts" element={<Alerts />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
