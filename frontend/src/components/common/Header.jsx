import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './Header.css';

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
        <button onClick={handleLogout} className="glass-button danger">
          <img src="/design/check-out.png" alt="Logout" style={{ width: '20px', height: '20px', marginRight: '8px' }} />
          Logout
        </button>
      </nav>
    </header>
  );
};

export default Header;