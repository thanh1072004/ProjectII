import React, { useState, useContext } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import RoleToggle from '../../role/RoleToggle';
import { UserContext } from '../../context/UserContext';
import './Register.css';

export default function Register({ role: initialRole, onToggle, onBack }) {
    const { setUser, setPrivateKey } = useContext(UserContext);
    const [role, setRole] = useState(initialRole || 'employee');
    const [code, setCode] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [rePassword, setRePassword] = useState('');
    const [verificationCode, setVerificationCode] = useState('');
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [tempPrivateKey, setTempPrivateKey] = useState(null);
    const navigate = useNavigate();

    const isManager = role === 'manager';

    const handleToggle = (selectedRole) => {
        setRole(selectedRole);
        onToggle?.(selectedRole);
    };

    const handleSendVerification = async (e) => {
        e.preventDefault();
    
        if (isSubmitting) {
            console.log('Submission already in progress, ignoring');
            return;
        }
    
        if (password !== rePassword) {
            console.error('Password do not match:', { password, rePassword });
            setError('Please re-enter password to match');
            return;
        }
    
        if (!email) {
            console.error('Missing email');
            setError('Email is required');
            return;
        }
    
        setIsSubmitting(true);
        setError(null);
    
        try {
            console.log('Send request to send verification code:', { email, role, password: '****', code });
            const res = await axios.post(
                `${import.meta.env.VITE_API_URL}/auth/send-verification-code`,
                { role, email, password, code: isManager ? code : undefined },
                { withCredentials: true }
            );
    
            console.log('Response from API sending code:', res.data);
            setTempPrivateKey(res.data.privateKey);
            setIsCodeSent(true);
            setError(null);
            alert('A verification code has been sent to your email.');
        } catch (err) {
            console.error('Error sending verification code:', {
                message: err.message,
                response: err.response?.data,
                status: err.response?.status
            });
            setError(err.response?.data?.error || 'Verification code sending failed. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleVerifyCode = async (e) => {
        e.preventDefault();

        if (isSubmitting) {
            console.log('Verification already in progress, ignoring');
            return;
        }

        setIsSubmitting(true);
        setError(null);

        try {
            console.log('Send code verification request:', { email, verificationCode });
            const res = await axios.post(
                `${import.meta.env.VITE_API_URL}/auth/verify-code`,
                { email, code: verificationCode, privateKey: tempPrivateKey },
                { withCredentials: true }
            );

            console.log('Response from the authentication API:', res.data);
            setUser(res.data.user);
            setPrivateKey(res.data.privateKey);
            sessionStorage.setItem('user', JSON.stringify(res.data.user));
            sessionStorage.setItem('privateKey', res.data.privateKey);
            sessionStorage.setItem('accessToken', res.data.token || '');
            alert(res.data.message || 'Sign up successfully');
            onBack ? onBack() : navigate('/home');
        } catch (err) {
            console.error('Code validation error:', {
                message: err.message,
                response: err.response?.data,
                status: err.response?.status
            });
            setError(err.response?.data?.error || 'The verification code is invalid or has expired.');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div
            className={`register-container ${isManager ? 'manager-mode' : ''}`}
            style={{
                backgroundColor: isManager ? '#d3f9d8' : '#ffffff',
                transition: 'background-color 0.5s ease',
            }}
        >
            <div
                className="register-box"
                style={{
                    backgroundColor: isManager ? '#4caf50' : '#ffffff',
                    color: isManager ? '#ffffff' : '#333',
                    transition: 'background-color 0.5s ease',
                }}
            >
                <h2 style={{ color: isManager ? '#ffffff' : '#4caf50' }}>
                    {isCodeSent ? 'Verify Your Email' : 'Create Account'}
                </h2>
                {!isCodeSent ? (
                    <form onSubmit={handleSendVerification}>
                        <RoleToggle onToggle={handleToggle} />
                        <div className={`input-group company-group ${isManager ? 'visible' : 'hidden'}`}>
                            <i className="fas fa-building"></i>
                            <input
                                type="password"
                                placeholder="Company Secret Code"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                            />
                        </div>
                        <div className="input-group">
                            <i className="fas fa-envelope"></i>
                            <input
                                type="email"
                                placeholder="Email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                            />
                        </div>
                        <div className="input-group">
                            <i className="fas fa-lock"></i>
                            <input
                                type="password"
                                placeholder="Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                            />
                        </div>
                        <div className="input-group">
                            <i className="fas fa-lock"></i>
                            <input
                                type="password"
                                placeholder="Confirm Password"
                                value={rePassword}
                                onChange={(e) => setRePassword(e.target.value)}
                                required
                            />
                        </div>
                        {error && <div className="error-message">{error}</div>}
                        <button
                            type="submit"
                            className="register-btn"
                            disabled={isSubmitting}
                            style={
                                isManager
                                    ? {
                                          backgroundColor: '#ffffff',
                                          color: '#4caf50',
                                          border: '2px solid #4caf50',
                                      }
                                    : {}
                            }
                        >
                            {isSubmitting ? 'Sending...' : 'Send Verification Code'}
                        </button>
                        <div className="register-footer">
                            <p>
                                Already have an account?{' '}
                                <a href="/login" onClick={() => onBack?.() || navigate('/login')}>
                                    Back to Login
                                </a>
                            </p>
                        </div>
                    </form>
                ) : (
                    <form onSubmit={handleVerifyCode}>
                        <div className="input-group">
                            <i className="fas fa-code"></i>
                            <input
                                type="text"
                                placeholder="Enter Verification Code"
                                value={verificationCode}
                                onChange={(e) => setVerificationCode(e.target.value)}
                                required
                            />
                        </div>
                        {error && <div className="error-message">{error}</div>}
                        <button
                            type="submit"
                            className="register-btn"
                            disabled={isSubmitting}
                            style={
                                isManager
                                    ? {
                                          backgroundColor: '#ffffff',
                                          color: '#4caf50',
                                          border: '2px solid #4caf50',
                                      }
                                    : {}
                            }
                        >
                            {isSubmitting ? 'Verifying...' : 'Verify Code'}
                        </button>
                        <div className="register-footer">
                            <p>
                                <button
                                    type="button"
                                    className="back-btn"
                                    onClick={() => setIsCodeSent(false)}
                                    style={
                                        isManager
                                            ? {
                                                  backgroundColor: '#ffffff',
                                                  color: '#4caf50',
                                                  border: '2px solid #4caf50',
                                              }
                                            : {}
                                    }
                                >
                                    Back to Register
                                </button>
                            </p>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
}