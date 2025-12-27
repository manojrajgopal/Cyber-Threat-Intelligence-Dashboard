import api from '../services/api';

export const ingestionApi = {
  // Submit single threat input
  submitSingleInput: async (inputData) => {
    
    try {
      const response = await api.post('/ingestion/single', inputData);
      
      if (response.data.data) {
        if (response.data.data.ai_prediction) {
          // AI prediction available
        }
      }
      
      return response.data;
      
    } catch (error) {
      // Throw the error response data if available, otherwise the error message
      throw error.response?.data || error.message;
    }
  },

  // Submit bulk input
  submitBulkInput: async (inputData) => {
    try {
      const response = await api.post('/ingestion/bulk', inputData);
      return response.data;
    } catch (error) {
      throw error.response?.data || error.message;
    }
  },

  // Upload file for ingestion
  uploadFile: async (file) => {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await api.post('/ingestion/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error) {
      throw error.response?.data || error.message;
    }
  },

  // Get ingestion jobs
  getIngestionJobs: async (params = {}) => {
    try {
      const response = await api.get('/ingestion/jobs', { params });
      return response.data;
    } catch (error) {
      throw error.response?.data || error.message;
    }
  },

  // Get specific ingestion job
  getIngestionJob: async (jobId) => {
    try {
      const response = await api.get(`/ingestion/jobs/${jobId}`);
      return response.data;
    } catch (error) {
      throw error.response?.data || error.message;
    }
  }
};