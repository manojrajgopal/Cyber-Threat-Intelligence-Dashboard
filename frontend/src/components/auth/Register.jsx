import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';

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
      console.log('Registration attempt with:', formData);

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
      console.error('Registration error:', error);
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
    <div className="glass-dashboard-bg min-h-screen flex items-center justify-center p-4">
      <div className="glass-floating-panel max-w-4xl w-full glass-fade-in">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Panel - Branding */}
          <div className="glass-card p-8 text-center">
            <div className="mb-6">
              <div className="text-6xl mb-4">🛡️</div>
              <h1 className="text-2xl font-bold mb-2">Join Cyber Threat Intelligence</h1>
              <p className="opacity-70">Create your secure account</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-sm opacity-70">
                Access advanced threat detection and real-time security analytics
              </p>
            </div>
          </div>

          {/* Right Panel - Registration Form */}
          <div className="glass-card p-8" ref={formRef}>
            <div className="mb-6">
              <h2 className="text-xl font-bold mb-2">Create Account</h2>
              <p className="opacity-70">Get started with threat intelligence</p>
            </div>

            {error && (
              <div className="glass-card p-4 mb-4 border-red-500/20 bg-red-500/10">
                <p className="text-red-300">{error}</p>
              </div>
            )}

            <form onSubmit={(e) => { e.preventDefault(); handleSubmit(); }} className="space-y-4">
              <div>
                <label className="glass-label">Username</label>
                <input
                  type="text"
                  name="username"
                  required
                  className="glass-input"
                  placeholder="Enter username"
                  value={formData.username}
                  onChange={handleChange}
                  disabled={loading}
                />
              </div>

              <div>
                <label className="glass-label">Email</label>
                <input
                  type="email"
                  name="email"
                  required
                  className="glass-input"
                  placeholder="Enter email"
                  value={formData.email}
                  onChange={handleChange}
                  disabled={loading}
                />
              </div>

              <div>
                <label className="glass-label">Password</label>
                <input
                  type="password"
                  name="password"
                  required
                  className="glass-input"
                  placeholder="Create password"
                  value={formData.password}
                  onChange={handleChange}
                  disabled={loading}
                />
              </div>

              <div>
                <label className="glass-label">Confirm Password</label>
                <input
                  type="password"
                  name="confirmPassword"
                  required
                  className="glass-input"
                  placeholder="Confirm password"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  disabled={loading}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="glass-button primary w-full"
              >
                {loading ? 'Creating Account...' : 'Register'}
              </button>

              <div className="text-center">
                <Link to="/login" className="opacity-70 hover:opacity-100">
                  Already have an account? Login here
                </Link>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;