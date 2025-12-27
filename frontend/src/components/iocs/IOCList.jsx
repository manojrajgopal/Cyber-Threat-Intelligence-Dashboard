import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';
import './IOCList.css';

const IOCList = () => {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedIoc, setSelectedIoc] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [iocToDelete, setIocToDelete] = useState(null);
  const itemsPerPage = 10;

  useEffect(() => {
    fetchIOCs();
  }, [typeFilter]);

  const fetchIOCs = async () => {
    try {
      const params = typeFilter ? { type_filter: typeFilter } : {};
      const response = await api.get('/iocs', { params });
      setIocs(response.data);
    } catch (error) {
      // Error fetching IOCs
    } finally {
      setLoading(false);
    }
  };

  const handleEnrich = async (iocId) => {
    try {
      await api.post(`/iocs/${iocId}/enrich`);
      // Refresh the list to show updated enrichment status
      fetchIOCs();
    } catch (error) {
      // Error enriching IOC
    }
  };

  const handleDelete = (iocId) => {
    setIocToDelete(iocId);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    try {
      await api.delete(`/iocs/${iocToDelete}`);
      // Refresh the list after deletion
      fetchIOCs();
      setShowDeleteModal(false);
      setIocToDelete(null);
    } catch (error) {
      alert('Failed to delete IOC. Please try again.');
      setShowDeleteModal(false);
      setIocToDelete(null);
    }
  };

  const handleRowClick = (ioc) => {
    setSelectedIoc(ioc);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedIoc(null);
  };

  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedIocs = iocs.slice(startIndex, startIndex + itemsPerPage);
  const totalPages = Math.ceil(iocs.length / itemsPerPage);

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading...
        </div>
      </div>
    );
  }

  return (
    <div className="glass-content">
      <div className="glass-card">
        <div className="glass-card-header">
          <h1 className="glass-card-title">IOCs</h1>
          <div className="flex space-x-4">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="glass-select"
            >
              <option value="">All Types</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
            </select>
          </div>
        </div>
        <div className="glass-card-content">
          <div className="glass-card overflow-hidden">
            <table className="glass-table w-full">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Risk Score</th>
                  <th>Source</th>
                  <th>Created</th>
                  <th>Enriched</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedIocs.map((ioc) => (
                  <tr key={ioc.id} onClick={() => handleRowClick(ioc)} className="cursor-pointer hover:bg-white/5">
                    <td>
                      <span className="px-2 py-1 text-xs rounded-full bg-blue-500/20 text-blue-300">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="font-medium">{ioc.value.length > 50 ? `${ioc.value.substring(0, 50)}...` : ioc.value}</td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        ioc.risk_score >= 0.7 ? 'bg-red-500/20 text-red-300' :
                        ioc.risk_score >= 0.4 ? 'bg-yellow-500/20 text-yellow-300' :
                        'bg-green-500/20 text-green-300'
                      }`}>
                        {(ioc.risk_score * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td className="opacity-70">{ioc.source}</td>
                    <td className="opacity-70 text-sm">
                      {ioc.created_at ? new Date(ioc.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        ioc.enriched ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-300'
                      }`}>
                        {ioc.enriched ? 'Yes' : 'No'}
                      </span>
                    </td>
                    <td className="space-x-2">
                      <Link
                        to={`/iocs/${ioc.id}/intelligence`}
                        className="glass-button secondary text-xs px-2 py-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        Intelligence
                      </Link>
                      {!ioc.enriched && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleEnrich(ioc.id); }}
                          className="glass-button primary text-xs px-2 py-1"
                        >
                          Enrich
                        </button>
                      )}
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(ioc.id); }}
                        className="glass-button danger text-xs px-2 py-1"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex justify-between items-center mt-4">
              <button
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                className="glass-button secondary text-xs px-3 py-1 previous-button"
              >
                Previous
              </button>
              <span className="text-sm opacity-70">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                className="glass-button secondary text-xs px-3 py-1 next-button"
              >
                Next
              </button>
            </div>
          )}

          {iocs.length === 0 && (
            <div className="text-center py-8 opacity-70">
              No IOCs found
            </div>
          )}
        </div>
      </div>

      {showModal && selectedIoc && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h2 className="glass-card-title">IOC Details</h2>
              <button onClick={closeModal} className="text-white opacity-70 hover:opacity-100 text-xl">×</button>
            </div>
            <div className="glass-card-content">
              <p><strong>Type:</strong> {selectedIoc.type}</p>
              <p><strong>Value:</strong> {selectedIoc.value}</p>
              <p><strong>Risk Score:</strong> {(selectedIoc.risk_score * 100).toFixed(0)}%</p>
              <p><strong>Source:</strong> {selectedIoc.source}</p>
              <p><strong>Enriched:</strong> {selectedIoc.enriched ? 'Yes' : 'No'}</p>
              <div className="mt-4 space-x-2">
                <Link to={`/iocs/${selectedIoc.id}`} className="glass-button primary" onClick={closeModal}>View</Link>
                <button onClick={closeModal} className="glass-button secondary">Close</button>
              </div>
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
              <p className="text-center py-4">Are you sure you want to delete this IOC?</p>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowDeleteModal(false);
                    setIocToDelete(null);
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

export default IOCList;