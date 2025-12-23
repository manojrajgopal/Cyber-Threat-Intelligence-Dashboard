import React from 'react';
import ThreatInputForm from '../components/inputs/ThreatInputForm';
import BulkUpload from '../components/inputs/BulkUpload';
import './ThreatInputPage.css';

const ThreatInputPage = () => {
  return (
    <div className="glass-content">
      <div className="glass-card">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Threat Intelligence Input</h1>
        </div>
        <div className="glass-card-content">
          <p className="opacity-70">
            Submit threat indicators for analysis and monitoring. You can submit individual indicators or upload bulk files.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatInputForm />
        <BulkUpload />
      </div>

      <div className="glass-card">
        <div className="glass-card-header">
          <h3 className="glass-card-title">Supported Indicator Types</h3>
        </div>
        <div className="glass-card-content">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="glass-card p-4">
              <strong className="block mb-1">IP Address</strong>
              <p className="text-sm opacity-70">IPv4 addresses</p>
            </div>
            <div className="glass-card p-4">
              <strong className="block mb-1">Domain</strong>
              <p className="text-sm opacity-70">Domain names</p>
            </div>
            <div className="glass-card p-4">
              <strong className="block mb-1">URL</strong>
              <p className="text-sm opacity-70">Web URLs</p>
            </div>
            <div className="glass-card p-4">
              <strong className="block mb-1">Hash</strong>
              <p className="text-sm opacity-70">MD5, SHA1, SHA256</p>
            </div>
          </div>
        </div>
      </div>

      <div className="glass-card">
        <div className="glass-card-header">
          <h3 className="glass-card-title">Important Notes</h3>
        </div>
        <div className="glass-card-content">
          <ul className="space-y-2 text-sm opacity-80">
            <li>• All submissions are automatically associated with your account</li>
            <li>• Bulk uploads are processed in the background and may take time</li>
            <li>• Invalid indicators will be rejected with error messages</li>
            <li>• Continuous monitoring can be enabled for ongoing threat tracking</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default ThreatInputPage;