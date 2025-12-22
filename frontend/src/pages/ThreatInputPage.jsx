import React from 'react';
import ThreatInputForm from '../components/inputs/ThreatInputForm';
import BulkUpload from '../components/inputs/BulkUpload';

const ThreatInputPage = () => {
  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Threat Intelligence Input</h1>
        <p className="text-gray-600 mt-2">
          Submit threat indicators for analysis and monitoring. You can submit individual indicators or upload bulk files.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatInputForm />
        <BulkUpload />
      </div>

      <div className="mt-8 bg-blue-50 p-4 rounded-lg">
        <h3 className="text-lg font-semibold text-blue-900 mb-2">Supported Indicator Types</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="bg-white p-3 rounded border">
            <strong className="text-blue-600">IP Address</strong>
            <p className="text-gray-600">IPv4 addresses</p>
          </div>
          <div className="bg-white p-3 rounded border">
            <strong className="text-blue-600">Domain</strong>
            <p className="text-gray-600">Domain names</p>
          </div>
          <div className="bg-white p-3 rounded border">
            <strong className="text-blue-600">URL</strong>
            <p className="text-gray-600">Web URLs</p>
          </div>
          <div className="bg-white p-3 rounded border">
            <strong className="text-blue-600">Hash</strong>
            <p className="text-gray-600">MD5, SHA1, SHA256</p>
          </div>
        </div>
      </div>

      <div className="mt-6 bg-yellow-50 p-4 rounded-lg">
        <h3 className="text-lg font-semibold text-yellow-900 mb-2">Important Notes</h3>
        <ul className="text-sm text-yellow-800 space-y-1">
          <li>• All submissions are automatically associated with your account</li>
          <li>• Bulk uploads are processed in the background and may take time</li>
          <li>• Invalid indicators will be rejected with error messages</li>
          <li>• Continuous monitoring can be enabled for ongoing threat tracking</li>
        </ul>
      </div>
    </div>
  );
};

export default ThreatInputPage;