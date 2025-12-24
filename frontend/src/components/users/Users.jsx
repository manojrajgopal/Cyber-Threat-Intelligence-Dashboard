import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Users.css';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [userToDelete, setUserToDelete] = useState(null);
  const [editingUser, setEditingUser] = useState(null);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    role_id: 1
  });

  const token = localStorage.getItem('token');

  useEffect(() => {
    fetchUsers();
    fetchRoles();
  }, []);

  const fetchRoles = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/users/roles', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRoles(response.data);
    } catch (err) {
      console.error('Failed to fetch roles', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/users/', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsers(response.data);
    } catch (err) {
      setError('Failed to fetch users');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingUser) {
        // Update user - assuming we have update endpoint
        await axios.put(`http://localhost:8000/api/users/${editingUser.id}`, formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
      } else {
        // Create user
        await axios.post('http://localhost:8000/api/users/', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
      }
      setShowModal(false);
      setEditingUser(null);
      setFormData({ username: '', email: '', password: '', role_id: 1 });
      fetchUsers();
    } catch (err) {
      setError('Failed to save user');
      console.error(err);
    }
  };

  const handleDelete = (userId) => {
    setUserToDelete(userId);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    try {
      await axios.delete(`http://localhost:8000/api/users/${userToDelete}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchUsers();
      setShowDeleteModal(false);
      setUserToDelete(null);
    } catch (err) {
      setError('Failed to delete user');
      console.error(err);
      setShowDeleteModal(false);
      setUserToDelete(null);
    }
  };

  const openModal = (user = null) => {
    if (user) {
      setEditingUser(user);
      setFormData({
        username: user.username,
        email: user.email,
        password: '',
        role_id: user.role?.id || 1
      });
    } else {
      setEditingUser(null);
      setFormData({ username: '', email: '', password: '', role_id: 1 });
    }
    setShowModal(true);
  };

  if (loading) return (
    <div className="glass-card">
      <div className="glass-card-content text-center py-16">
        Loading...
      </div>
    </div>
  );
  if (error) return (
    <div className="glass-card">
      <div className="glass-card-content text-center py-16 text-red-300">
        {error}
      </div>
    </div>
  );

  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">User Management</h1>
          <button
            onClick={() => openModal()}
            className="glass-button primary"
          >
            Add User
          </button>
        </div>
      </div>

      <div className="glass-card glass-fade-in overflow-hidden">
        <div className="glass-card-content">
          <div className="overflow-x-auto">
            <table className="glass-table w-full">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td className="font-medium">{user.username}</td>
                    <td className="opacity-70">{user.email}</td>
                    <td>
                      <span className="px-2 py-1 text-xs rounded-full bg-blue-500/20 text-blue-300">
                        {user.role?.name || 'No Role'}
                      </span>
                    </td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        user.is_active ? 'bg-green-500/20 text-green-300' : 'bg-red-500/20 text-red-300'
                      }`}>
                        {user.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td>
                      <div className="flex gap-2">
                        <button
                          onClick={() => openModal(user)}
                          className="glass-button secondary text-xs px-2 py-1"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(user.id)}
                          className="glass-button danger text-xs px-2 py-1"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 modal-overlay flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h3 className="glass-card-title">
                {editingUser ? 'Edit User' : 'Add User'}
              </h3>
            </div>
            <div className="glass-card-content">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="glass-label">Username</label>
                  <input
                    type="text"
                    value={formData.username}
                    onChange={(e) => setFormData({...formData, username: e.target.value})}
                    className="glass-input"
                    required
                  />
                </div>
                <div>
                  <label className="glass-label">Email</label>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    className="glass-input"
                    required
                  />
                </div>
                {!editingUser && (
                  <div>
                    <label className="glass-label">Password</label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({...formData, password: e.target.value})}
                      className="glass-input"
                      required
                    />
                  </div>
                )}
                <div>
                  <label className="glass-label">Role</label>
                  <select
                    value={formData.role_id}
                    onChange={(e) => setFormData({...formData, role_id: parseInt(e.target.value)})}
                    className="glass-select"
                    required
                  >
                    {roles.map((role) => (
                      <option key={role.id} value={role.id}>
                        {role.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="glass-button secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="glass-button primary"
                  >
                    {editingUser ? 'Update' : 'Create'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {showDeleteModal && (
        <div className="fixed inset-0 modal-overlay flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h3 className="glass-card-title">Confirm Delete</h3>
            </div>
            <div className="glass-card-content">
              <p className="text-center py-4">Are you sure you want to delete this user?</p>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowDeleteModal(false);
                    setUserToDelete(null);
                  }}
                  className="glass-button secondary"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={confirmDelete}
                  className="glass-button danger"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Users;