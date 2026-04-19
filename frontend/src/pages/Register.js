import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { Shield, Eye, EyeOff } from 'lucide-react';
import LanguageSwitcher from '../components/LanguageSwitcher';
import './Login.css';

const FULL_NAME_REGEX = /^[a-zA-ZÀ-ÖØ-öø-ÿА-яЁёԱ-Ֆա-ֆ]{2,}(\s[a-zA-ZÀ-ÖØ-öø-ÿА-яЁёԱ-Ֆա-ֆ]{2,})+$/;
const EMAIL_REGEX    = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function Register() {
  const { t } = useTranslation();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [passwordErrors, setPasswordErrors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [registered, setRegistered] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const validatePassword = (pwd) => {
    const errors = [];
    if (pwd.length < 8)                errors.push(t('register.pwdMinLength'));
    if (!/[A-Z]/.test(pwd))            errors.push(t('register.pwdUppercase'));
    if (!/[0-9]/.test(pwd))            errors.push(t('register.pwdNumber'));
    if (!/[^a-zA-Z0-9]/.test(pwd))     errors.push(t('register.pwdSpecial'));
    return errors;
  };

  const handlePasswordChange = (e) => {
    const val = e.target.value;
    setPassword(val);
    setPasswordErrors(val ? validatePassword(val) : []);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!FULL_NAME_REGEX.test(fullName.trim())) {
      setError(t('register.invalidFullName'));
      return;
    }

    if (!EMAIL_REGEX.test(email.trim())) {
      setError(t('register.invalidEmail'));
      return;
    }

    const pwErrors = validatePassword(password);
    if (pwErrors.length > 0) {
      setPasswordErrors(pwErrors);
      return;
    }

    setLoading(true);
    try {
      await register(email, password, fullName);
      setRegistered(true);
    } catch (err) {
      setError(err.response?.data?.detail || t('toast.registerFailed'));
    } finally {
      setLoading(false);
    }
  };

  if (registered) {
    return (
      <div className="login-container">
        <div className="login-box">
          <LanguageSwitcher />
          <div className="login-header">
            <Shield size={48} className="logo-icon" />
            <h1>{t('register.checkEmailTitle')}</h1>
            <p>{t('register.checkEmailMsg', { email })}</p>
          </div>
          <div className="verify-notice">
            <p>{t('register.checkEmailHint')}</p>
          </div>
          <div className="login-footer">
            <p>
              {t('register.haveAccount')} <Link to="/login">{t('register.signIn')}</Link>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <LanguageSwitcher />

        <div className="login-header">
          <Shield size={48} className="logo-icon" />
          <h1>{t('register.title')}</h1>
          <p>{t('register.subtitle')}</p>
        </div>

        {error && (
          <div className="error-message">{error}</div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="fullName">{t('register.fullName')}</label>
            <input
              id="fullName"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="John Doe"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="email">{t('register.email')}</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">{t('register.password')}</label>
            <div className="input-password-wrapper">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={handlePasswordChange}
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                className="btn-toggle-password"
                onClick={() => setShowPassword((v) => !v)}
                tabIndex={-1}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {passwordErrors.length > 0 && (
              <ul className="password-requirements">
                {passwordErrors.map((err, i) => (
                  <li key={i}>✗ {err}</li>
                ))}
              </ul>
            )}
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? t('register.creatingAccount') : t('register.signUp')}
          </button>
        </form>

        <div className="login-footer">
          <p>
            {t('register.haveAccount')} <Link to="/login">{t('register.signIn')}</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Register;
