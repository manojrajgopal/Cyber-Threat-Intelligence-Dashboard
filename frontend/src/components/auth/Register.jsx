import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import './Register.css';

const Register = ({ api }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [requirements, setRequirements] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    number: false,
    special: false
  });
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
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    
    if (error) setError('');
    
    if (name === 'password') {
      checkPasswordStrength(value);
    }
  };

  const checkPasswordStrength = (password) => {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    setRequirements(checks);
    
    const score = Object.values(checks).filter(Boolean).length * 20;
    setPasswordStrength(score);
  };

  const getPasswordStrengthColor = () => {
    if (passwordStrength >= 80) return '#10b981';
    if (passwordStrength >= 60) return '#f59e0b';
    if (passwordStrength >= 40) return '#f97316';
    return '#ef4444';
  };

  const getPasswordStrengthLabel = () => {
    if (passwordStrength >= 80) return 'Strong';
    if (passwordStrength >= 60) return 'Good';
    if (passwordStrength >= 40) return 'Fair';
    return 'Weak';
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      
      if (formRef.current) {
        formRef.current.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
          formRef.current.style.animation = '';
        }, 500);
      }
      return;
    }

    try {

      if (formData.username && formData.email && formData.password) {
        const response = await api.post('/auth/register', {
          username: formData.username,
          email: formData.email,
          password: formData.password
        });

        // Store the token and user info
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('user', formData.username);

        // Show success animation
        if (formRef.current) {
          const successMsg = document.createElement('div');
          successMsg.className = 'success-message';
          successMsg.innerHTML = `
            <span class="success-icon">🎉</span>
            <span class="success-text">Account created successfully! Redirecting...</span>
          `;
          formRef.current.prepend(successMsg);

          setTimeout(() => {
            successMsg.style.animation = 'fadeOutUp 0.5s ease forwards';
            setTimeout(() => {
              successMsg.remove();
            }, 500);
          }, 2000);

          formRef.current.style.transform = 'scale(0.95)';
          formRef.current.style.opacity = '0.8';

          setTimeout(() => {
            navigate('/dashboard');
          }, 2500);
        }
      } else {
        throw new Error('Please fill all fields');
      }
    } catch (error) {
      setError(error.response?.data?.detail || 'Registration failed');
      
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

        {/* Register-specific stats */}
        <div className="stats-section">
          <div className="stat-item">
            <div className="stat-value">15,000+</div>
            <div className="stat-label">Organizations Secured</div>
          </div>
          <div className="stat-divider"></div>
          <div className="stat-item">
            <div className="stat-value">99.9%</div>
            <div className="stat-label">Uptime SLA</div>
          </div>
          <div className="stat-divider"></div>
          <div className="stat-item">
            <div className="stat-value">24/7</div>
            <div className="stat-label">Security Monitoring</div>
          </div>
        </div>
      </div>
      
      {/* Right Panel - Registration Form */}
      <div className="login-right-panel">
        <div className="access-container">
          <div className="access-header">
            <div className="access-header-content">
              <h2 className="access-title">Create Your Account</h2>
              <p className="access-subtitle">Begin your security journey in seconds</p>
            </div>
          </div>
          
          <div className="access-container" ref={formRef}>
            <div className="access-notice">
              <div className="notice-icon">✨</div>
              <div className="notice-text">
                Create your account to access real-time threat intelligence, advanced analytics, and collaborative security tools.
              </div>
            </div>
            
            <form className="login-form" onSubmit={handleSubmit}>
              {error && (
                <div className="error-message-glass">
                  <span className="error-icon">⚠️</span>
                  <span className="error-text">{error}</span>
                </div>
              )}
              
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
                  <span className="label-icon">✉️</span>
                  <span className="label-text">Email Address</span>
                </label>
                <div className="input-wrapper-glass">
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    className="login-input-glass"
                    placeholder="your.email@company.com"
                    value={formData.email}
                    onChange={handleChange}
                    disabled={loading}
                  />
                </div>
              </div>
              
              <div className="input-group-glass">
                <label className="input-label-glass">
                  <span className="label-icon">🔐</span>
                  <span className="label-text">Password</span>
                </label>
                <div className="input-wrapper-glass">
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    className="login-input-glass"
                    placeholder="Create a strong password"
                    value={formData.password}
                    onChange={handleChange}
                    disabled={loading}
                  />
                  
                  {formData.password && (
                    <div className="password-strength-glass">
                      <div className="strength-meter">
                        <div 
                          className="strength-progress"
                          style={{
                            width: `${passwordStrength}%`,
                            backgroundColor: getPasswordStrengthColor()
                          }}
                        ></div>
                      </div>
                      <div className="strength-label-glass">
                        <span>Strength: </span>
                        <span className="strength-value" style={{ color: getPasswordStrengthColor() }}>
                          {getPasswordStrengthLabel()}
                        </span>
                      </div>
                      
                      <div className="requirements-grid">
                        <div className={`requirement-item ${requirements.length ? 'met' : ''}`}>
                          <span className="req-icon">{requirements.length ? '✓' : '○'}</span>
                          <span className="req-text">8+ characters</span>
                        </div>
                        <div className={`requirement-item ${requirements.uppercase ? 'met' : ''}`}>
                          <span className="req-icon">{requirements.uppercase ? '✓' : '○'}</span>
                          <span className="req-text">Uppercase</span>
                        </div>
                        <div className={`requirement-item ${requirements.lowercase ? 'met' : ''}`}>
                          <span className="req-icon">{requirements.lowercase ? '✓' : '○'}</span>
                          <span className="req-text">Lowercase</span>
                        </div>
                        <div className={`requirement-item ${requirements.number ? 'met' : ''}`}>
                          <span className="req-icon">{requirements.number ? '✓' : '○'}</span>
                          <span className="req-text">Number</span>
                        </div>
                        <div className={`requirement-item ${requirements.special ? 'met' : ''}`}>
                          <span className="req-icon">{requirements.special ? '✓' : '○'}</span>
                          <span className="req-text">Special char</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="input-group-glass">
                <label className="input-label-glass">
                  <span className="label-icon">🔒</span>
                  <span className="label-text">Confirm Password</span>
                </label>
                <div className="input-wrapper-glass">
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    required
                    className="login-input-glass"
                    placeholder="Re-enter your password"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    disabled={loading}
                  />
                  
                  {formData.confirmPassword && formData.password && (
                    <div className={`password-match ${formData.password === formData.confirmPassword ? 'match' : 'mismatch'}`}>
                      <span className="match-icon">
                        {formData.password === formData.confirmPassword ? '✓' : '✗'}
                      </span>
                      <span className="match-text">
                        {formData.password === formData.confirmPassword ? 'Passwords match' : 'Passwords do not match'}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="login-options">
                <label className="checkbox-container">
                  <input type="checkbox" className="hidden-checkbox" required />
                  <div className="custom-checkbox">
                    <svg className="checkmark" viewBox="0 0 12 10">
                      <polyline points="1.5 6 4.5 9 10.5 1"></polyline>
                    </svg>
                  </div>
                  <span className="checkbox-label">
                    I agree to the <Link to="/terms" className="terms-link-glass">Terms of Service</Link> and <Link to="/privacy" className="terms-link-glass">Privacy Policy</Link>
                  </span>
                </label>
              </div>
              
              <button
                type="button"
                onClick={handleSubmit}
                disabled={loading}
                className="login-button-glass"
              >
                {loading ? (
                  <>
                    <span className="button-loader"></span>
                    Creating Secure Account...
                  </>
                ) : (
                  <>
                    <span className="button-icon">🚀</span>
                    <span className="button-text">Create Secure Account</span>
                    <span className="button-arrow">›</span>
                  </>
                )}
              </button>
              
              <div className="alternative-auth-glass">
                <div className="auth-divider">
                  <span className="divider-line"></span>
                  <span className="divider-text">or</span>
                  <span className="divider-line"></span>
                </div>
                
                <div className="register-prompt">
                  <span className="prompt-text">Already have an account?</span>
                  <Link to="/login" className="register-link-glass">
                    Sign In Here
                  </Link>
                </div>
              </div>
            </form>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Register;