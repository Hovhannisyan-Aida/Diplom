import axios from 'axios';

const API_URL = 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  }),
  getCurrentUser: () => api.get('/auth/me'),
};

export const scansAPI = {
  getAll: () => api.get('/scans/'),
  getById: (id) => api.get(`/scans/${id}`),
  create: (data) => api.post('/scans/', data),
  getVulnerabilities: (id) => api.get(`/scans/${id}/vulnerabilities`),
  export: (id) => api.get(`/scans/${id}/export`),
  getStatistics: () => api.get('/scans/statistics/summary'),
};

export default api;