import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// API service
import api from './services/api';

// Components
import Header from './components/common/Header';
import Footer from './components/common/Footer';
import Sidebar from './components/common/Sidebar';
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import Dashboard from './components/dashboard/Dashboard';
import ThreatInputPage from './pages/ThreatInputPage';
import AIInsightsPage from './pages/AIInsightsPage';
import ThreatLifecyclePage from './pages/ThreatLifecyclePage';
import AccountThreatsPage from './pages/AccountThreatsPage';
import IOCList from './components/iocs/IOCList';
import IOCDetails from './components/iocs/IOCDetails';
import IOCIntelligence from './components/iocs/IOCIntelligence';
import AlertsTable from './components/alerts/AlertsTable';
import Reports from './components/reports/Reports';
import GeoMap from './components/maps/GeoMap';
import Users from './components/users/Users';
import RiskManagement from './components/dashboard/RiskManagement';

// Auth check
const isAuthenticated = () => {
  return localStorage.getItem('token') !== null;
};

// Protected Route component
const ProtectedRoute = ({ children }) => {
  return isAuthenticated() ? children : <Navigate to="/login" />;
};

// Layout component
const Layout = ({ children }) => {
  return (
    <div className="glass-main-container">
      <div className="glass-floating-panel glass-fade-in">
        <Header />
        <div className="glass-layout">
          <Sidebar />
          <main className="glass-content">
            {children}
          </main>
        </div>
        <Footer />
      </div>
    </div>
  );
};

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login api={api} />} />
          <Route path="/register" element={<Register api={api} />} />
          
          {/* Protected routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout>
                  <Dashboard />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/threat-input"
            element={
              <ProtectedRoute>
                <Layout>
                  <ThreatInputPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/ai-insights"
            element={
              <ProtectedRoute>
                <Layout>
                  <AIInsightsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/threat-lifecycle"
            element={
              <ProtectedRoute>
                <Layout>
                  <ThreatLifecyclePage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/account-threats"
            element={
              <ProtectedRoute>
                <Layout>
                  <AccountThreatsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/iocs/:id/intelligence"
            element={
              <ProtectedRoute>
                <Layout>
                  <IOCIntelligence />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/iocs"
            element={
              <ProtectedRoute>
                <Layout>
                  <IOCList />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/iocs/:id"
            element={
              <ProtectedRoute>
                <Layout>
                  <IOCDetails />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <Layout>
                  <AlertsTable />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Layout>
                  <Reports />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/map"
            element={
              <ProtectedRoute>
                <Layout>
                  <GeoMap />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/users"
            element={
              <ProtectedRoute>
                <Layout>
                  <Users />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/risk"
            element={
              <ProtectedRoute>
                <Layout>
                  <RiskManagement />
                </Layout>
              </ProtectedRoute>
            }
          />
          
          {/* Default redirect */}
          <Route path="/" element={<Navigate to="/dashboard" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
