import React from 'react';

const Footer = () => {
  return (
    <footer className="footer-container">
      <div className="footer-content">
        <div className="footer-main">
          <p className="footer-text">
            &copy; 2024 Cyber Threat Intelligence Dashboard. All rights reserved.
          </p>
          
          {/* Optional additional footer elements */}
          <div className="footer-links">
            <a href="/privacy" className="footer-link">Privacy Policy</a>
            <span className="footer-divider">•</span>
            <a href="/terms" className="footer-link">Terms of Service</a>
            <span className="footer-divider">•</span>
            <a href="/contact" className="footer-link">Contact</a>
          </div>
        </div>
        
        <div className="footer-security">
          <div className="security-badge">
            <span className="badge-icon">🔒</span>
            <span className="badge-text">Secure Connection</span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;