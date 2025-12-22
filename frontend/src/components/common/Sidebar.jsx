import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Sidebar.css';

const Sidebar = () => {
  const location = useLocation();

  const menuItems = [
    { path: '/dashboard', label: 'Dashboard', icon: '📊' },
    { path: '/threat-input', label: 'Threat Input', icon: '📥' },
    { path: '/iocs', label: 'IOCs', icon: '🔍' },
    { path: '/ai-insights', label: 'AI Insights', icon: '🤖' },
    { path: '/threat-lifecycle', label: 'Lifecycle', icon: '🔄' },
    { path: '/account-threats', label: 'My Threats', icon: '👤' },
    { path: '/alerts', label: 'Alerts', icon: '🚨' },
    { path: '/reports', label: 'Reports', icon: '📄' },
    { path: '/map', label: 'Map', icon: '🗺️' },
    { path: '/users', label: 'Users', icon: '👥' },
  ];

  return (
    <aside className="sidebar-container">
      <nav>
        <ul className="sidebar-menu">
          {menuItems.map((item) => (
            <li key={item.path} className="sidebar-item">
              <Link
                to={item.path}
                className={`sidebar-link ${
                  location.pathname === item.path ? 'sidebar-link-active' : ''
                }`}
              >
                <span className="sidebar-icon">{item.icon}</span>
                <span className="sidebar-label">{item.label}</span>
                {location.pathname === item.path && (
                  <span className="active-indicator" />
                )}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
};

export default Sidebar;