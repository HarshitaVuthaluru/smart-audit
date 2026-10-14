import axios from "axios";

const API_URL = "http://localhost:3000/api";

// Create axios instance with base URL
const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Helper function for file uploads (uses different content type)
const fileApi = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "multipart/form-data",
  },
});

// Contract upload and fetching
export const uploadContract = (formData) => {
  return fileApi.post("/upload-contract", formData);
};

export const generateSecureContract = (formData) => {
  return fileApi.post("/generate-secure-contract", formData);
};

export const fetchSecureGeneration = (generationId) => {
  return api.get(`/secure-generations/${generationId}`);
};

// Analysis
export const startAnalysis = (data) => {
  return api.post("/analyze", data);
};

// Status and results
export const fetchContractStatus = (jobId) => {
  return api.get(`/status/${jobId}`);
};

export const fetchContractResults = (jobId) => {
  return api.get(`/results/${jobId}`);
};

export default api;
