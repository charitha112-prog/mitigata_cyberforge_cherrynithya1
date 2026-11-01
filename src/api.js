import axios from "axios";
const baseURL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
export const api = axios.create({baseURL, timeout: 120000});
api.interceptors.request.use(config => {
  const token = localStorage.getItem("integratex_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});
export const errorMessage = e => e?.response?.data?.detail || e?.response?.data?.message || e.message || "Request failed";
export const apiCall = async (method, path, data) => (await api({method,url:path,data})).data;
