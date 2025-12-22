import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

const Header = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <header className="glass-nav-bar">
      <h1 className="glass-nav-title">
        <Link to="/dashboard">
          Cyber Threat Intelligence Dashboard
        </Link>
      </h1>
      <nav className="glass-nav-actions">
        <Link to="/dashboard" className="glass-button secondary">
          Dashboard
        </Link>
        <Link to="/iocs" className="glass-button secondary">
          IOCs
        </Link>
        <Link to="/alerts" className="glass-button secondary">
          Alerts
        </Link>
        <Link to="/reports" className="glass-button secondary">
          Reports
        </Link>
        <button onClick={handleLogout} className="glass-button danger">
          Logout
        </button>
      </nav>
    </header>
  );
};

export default Header;