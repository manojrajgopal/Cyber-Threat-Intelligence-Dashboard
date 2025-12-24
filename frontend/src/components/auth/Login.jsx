import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import './Login.css';

const Login = ({ api }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const containerRef = useRef(null);
  const formRef = useRef(null);
  const leftPanelRef = useRef(null);

  useEffect(() => {
    // Animate left panel entrance
    if (leftPanelRef.current) {
      leftPanelRef.current.style.transform = 'translateX(-30px)';
      leftPanelRef.current.style.opacity = '0';
      
      setTimeout(() => {
        leftPanelRef.current.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        leftPanelRef.current.style.transform = 'translateX(0)';
        leftPanelRef.current.style.opacity = '1';
      }, 300);
    }

    // Animate form entrance
    if (formRef.current) {
      formRef.current.style.transform = 'translateX(30px)';
      formRef.current.style.opacity = '0';
      
      setTimeout(() => {
        formRef.current.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        formRef.current.style.transform = 'translateX(0)';
        formRef.current.style.opacity = '1';
      }, 500);
    }
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    if (error) setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      console.log('Login attempt with:', formData);

      if (formData.username && formData.password) {
        const response = await api.post('/auth/login', {
          username: formData.username,
          password: formData.password
        });

        // Store the token and user info
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('user', formData.username);

        if (formRef.current) {
          formRef.current.style.transform = 'scale(0.95)';
          formRef.current.style.opacity = '0.8';

          setTimeout(() => {
            navigate('/dashboard');
          }, 300);
        }
      } else {
        throw new Error('Please enter credentials');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError(error.response?.data?.detail || 'Invalid username or password');

      if (formRef.current) {
        formRef.current.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
          formRef.current.style.animation = '';
        }, 500);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container" ref={containerRef}>
      {/* Animated Background Elements */}
      <div className="bg-grid"></div>
      <div className="bg-floating shape-1"></div>
      <div className="bg-floating shape-2"></div>
      <div className="bg-floating shape-3"></div>
      <div className="bg-floating shape-4"></div>
      
      {/* Left Panel - Video Display */}
      <div className="login-left-panel" ref={leftPanelRef}>
        <div className="security-header">
          <div className="security-brand">
            <div className="shield-logo">🛡️</div>
            <div className="security-title">
              <span className="title-main">Threat Intelligence</span>
              <span className="title-sub">Security Portal</span>
            </div>
          </div>
          
          <div className="security-status">
            <div className="status-indicator active"></div>
            <span className="status-text">Security Systems Online</span>
          </div>
        </div>

        {/* Video Container */}
        <div className="video-container">
          <video
            className="security-video"
            autoPlay
            loop
            muted
            playsInline
          >
            <source src="/design/login.mp4" type="video/mp4" />
            Your browser does not support the video tag.
          </video>
          
          
          {/* Video Overlay Gradient */}
          <div className="video-overlay-gradient"></div>
        </div>
      </div>
      
      {/* Right Panel - Login Form */}
      <div className="login-right-panel">
        {error && (
          <div className="error-bar-top">
            <span className="error-bar-icon">⚠️</span>
            <span className="error-bar-text">{error}</span>
          </div>
        )}
        <div className="access-container">
          <div className="access-header">
            <div className="access-header-content">
              <h2 className="access-title">Secure Authentication</h2>
              <p className="access-subtitle">Access threat intelligence dashboard</p>
            </div>
          </div>
          
          <div className="access-container" ref={formRef}>
            <div className="access-notice">
              <div className="notice-icon">⚠️</div>
              <div className="notice-text">
                This system contains sensitive security information. Access is monitored and recorded.
              </div>
            </div>
            
            <form className="login-form" onSubmit={handleSubmit}>
              <div className="input-group-glass">
                <label className="input-label-glass">
                  <span className="label-icon">👤</span>
                  <span className="label-text">Username</span>
                </label>
                <div className="input-wrapper-glass">
                  <input
                    id="username"
                    name="username"
                    type="text"
                    required
                    className="login-input-glass"
                    placeholder="Enter your username"
                    value={formData.username}
                    onChange={handleChange}
                    disabled={loading}
                  />
                </div>
              </div>
              
              <div className="input-group-glass">
                <label className="input-label-glass">
                  <span className="label-icon">🔑</span>
                  <span className="label-text">Password</span>
                </label>
                <div className="input-wrapper-glass">
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    className="login-input-glass"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={handleChange}
                    disabled={loading}
                  />
                </div>
                <div className="password-options">
                  <Link to="/forgot-password" className="forgot-link-glass">
                    Forgot password?
                  </Link>
                </div>
              </div>
              
              <div className="login-options">
                <label className="checkbox-container">
                  <input type="checkbox" className="hidden-checkbox" />
                  <div className="custom-checkbox">
                    <svg className="checkmark" viewBox="0 0 12 10">
                      <polyline points="1.5 6 4.5 9 10.5 1"></polyline>
                    </svg>
                  </div>
                  <span className="checkbox-label">Remember this device</span>
                </label>
              </div>
              
              <button
                type="submit"
                disabled={loading}
                className="login-button-glass"
              >
                {loading ? (
                  <>
                    <span className="button-loader"></span>
                    Authenticating...
                  </>
                ) : (
                  <>
                    <span className="button-icon">→</span>
                    <span className="button-text">Access Dashboard</span>
                    <span className="button-arrow">›</span>
                  </>
                )}
              </button>
              
              <div className="alternative-auth-glass">
                <div className="auth-divider">
                  <span className="divider-line"></span>
                  <span className="divider-text">or authenticate with</span>
                  <span className="divider-line"></span>
                </div>
              </div>
              
              <div className="register-prompt">
                <span className="prompt-text">Need access?</span>
                <Link to="/register" className="register-link-glass">
                  Request account access
                </Link>
              </div>
            </form>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Login;