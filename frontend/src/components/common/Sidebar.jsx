import React from 'react';
import { Link, useLocation } from 'react-router-dom';

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
    <aside className="glass-sidebar">
      <nav>
        <ul>
          {menuItems.map((item) => (
            <li key={item.path}>
              <Link
                to={item.path}
                className={`glass-nav-item ${
                  location.pathname === item.path ? 'active' : ''
                }`}
              >
                <span className="glass-nav-icon">{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
};

export default Sidebar;