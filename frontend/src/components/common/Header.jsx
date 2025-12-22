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
    <header className="header-container">
      <div className="header-content">
        {/* Brand/Logo on left */}
        <Link to="/" className="header-brand">Cyber Threat Intelligence Dashboard</Link>
        {/* Logout on right */}
        <button onClick={handleLogout} className="logout-btn-left">
          <img 
            src="/design/check-out.png" 
            alt="Logout" 
            className="logout-icon-img"
          />
          <span className="logout-text">Logout</span>
        </button>
      </div>
    </header>
  );
};

export default Header;