import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

const Header = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <header className="bg-blue-600 text-white shadow-lg">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link to="/dashboard" className="text-xl font-bold">
          CTI Dashboard
        </Link>
        <nav className="space-x-4">
          <Link to="/dashboard" className="hover:underline">Dashboard</Link>
          <Link to="/iocs" className="hover:underline">IOCs</Link>
          <Link to="/alerts" className="hover:underline">Alerts</Link>
          <Link to="/reports" className="hover:underline">Reports</Link>
          <button onClick={handleLogout} className="hover:underline">
            Logout
          </button>
        </nav>
      </div>
    </header>
  );
};

export default Header;