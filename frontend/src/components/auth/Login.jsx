import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';

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
    <div className="glass-dashboard-bg min-h-screen flex items-center justify-center p-4">
      <div className="glass-floating-panel max-w-4xl w-full glass-fade-in">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Panel - Branding */}
          <div className="glass-card p-8 text-center">
            <div className="mb-6">
              <div className="text-6xl mb-4">🛡️</div>
              <h1 className="text-2xl font-bold mb-2">Cyber Threat Intelligence</h1>
              <p className="opacity-70">Security Dashboard</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-sm opacity-70">
                Advanced threat detection and intelligence analysis platform
              </p>
            </div>
          </div>

          {/* Right Panel - Login Form */}
          <div className="glass-card p-8" ref={formRef}>
            <div className="mb-6">
              <h2 className="text-xl font-bold mb-2">Secure Login</h2>
              <p className="opacity-70">Access your dashboard</p>
            </div>

            {error && (
              <div className="glass-card p-4 mb-4 border-red-500/20 bg-red-500/10">
                <p className="text-red-300">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
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
                <label className="glass-label">Password</label>
                <input
                  type="password"
                  name="password"
                  required
                  className="glass-input"
                  placeholder="Enter password"
                  value={formData.password}
                  onChange={handleChange}
                  disabled={loading}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="glass-button primary w-full"
              >
                {loading ? 'Authenticating...' : 'Login'}
              </button>

              <div className="text-center">
                <Link to="/register" className="opacity-70 hover:opacity-100">
                  Need an account? Register here
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