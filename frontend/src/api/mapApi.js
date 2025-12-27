import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

export const getMapIOCs = async () => {
    try {
        const response = await axios.get(`${API_BASE_URL}/iocs/map`);
        return response.data;
    } catch (error) {
        return [];
    }
};