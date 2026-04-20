import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    if (token) {
      loadUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const loadUser = async () => {
    try {
      const response = await authAPI.getCurrentUser();
      setUser(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        try {
          const { data } = await authAPI.refresh();
          localStorage.setItem('token', data.access_token);
          const retried = await authAPI.getCurrentUser();
          setUser(retried.data);
        } catch {
          logout();
        }
      } else {
        logout();
      }
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    const response = await authAPI.login(formData);
    const { access_token } = response.data;
    
    localStorage.setItem('token', access_token);
    setToken(access_token);
    await loadUser();
  };

  const register = async (email, password, fullName) => {
    await authAPI.register({
      email,
      password,
      full_name: fullName,
    });
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch {
    }
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  const deleteAccount = async () => {
    await authAPI.deleteAccount();
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    deleteAccount,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};