import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Sidebar.css';

const Sidebar = () => {
  const location = useLocation();

  const menuItems = [
    { path: '/dashboard', label: 'Dashboard', icon: <img src="/design/dashboard.png" alt="Dashboard" /> },
    { path: '/threat-input', label: 'Threat Input', icon: <img src="/design/threat.png" alt="Threat Input" /> },
    { path: '/iocs', label: 'IOCs', icon: <img src="/design/ioc.png" alt="IOCs" /> },
    { path: '/ai-insights', label: 'AI Insights', icon: <img src="/design/ai.png" alt="AI Insights" /> },
    { path: '/threat-lifecycle', label: 'Lifecycle', icon: <img src="/design/Lifecycle.png" alt="Lifecycle" /> },
    { path: '/account-threats', label: 'My Threats', icon: <img src="/design/my threat.png" alt="My Threats" /> },
    { path: '/alerts', label: 'Alerts', icon: <img src="/design/alert.png" alt="Alerts" /> },
    { path: '/reports', label: 'Reports', icon: <img src="/design/report.png" alt="Reports" /> },
    { path: '/map', label: 'Map', icon: <img src="/design/map.png" alt="Map" /> },
    { path: '/users', label: 'Users', icon: <img src="/design/users.png" alt="Users" /> },
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