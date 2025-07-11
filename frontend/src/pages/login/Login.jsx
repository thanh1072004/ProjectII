import './Login.css';
import loginImage from '../../assets/login-illustration.png';
import RoleToggle from '../../role/RoleToggle';
import Register from '../register/Register';
import { useState, useContext } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import { decryptPrivateKey } from '../../utils/cryptoUtils';

export default function Login() {
    const { setUser, setPrivateKey } = useContext(UserContext);
    const [role, setRole] = useState('employee');
    const [showRegister, setShowRegister] = useState(false);
    const [code, setCode] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        const isManager = role === 'manager';

        try {
            if (isManager && code !== import.meta.env.VITE_SECRET_CODE) {
                console.error('Secret code incorrect:', code);
                alert('Secret code incorrect');
                return;
            }

            console.log('Send login request:', { email, role, password: '****' });
            const res = await axios.post(
                `${import.meta.env.VITE_API_URL}/auth/login`,
                { email, password, role }, 
                { withCredentials: true }
            );

            console.log('Response from login API:', res.data);

            const { user: loginUser, privateKey, token } = res.data;
            if (!loginUser) {
                console.error('API response missing user information');
                alert('Invalid user data');
                return;
            }

            if (!privateKey && !loginUser.encryptedPrivateKey) {
                console.error('Missing encryptedPrivateKey or privateKey in response');
                alert('The encryption private key is not present in the user data');
                return;
            }

            let finalPrivateKey = privateKey;
            if (!privateKey && loginUser.encryptedPrivateKey) {
                console.log('Decrypting the private key with encryptedPrivateKey:', loginUser.encryptedPrivateKey);
                try {
                    finalPrivateKey = await decryptPrivateKey(loginUser.encryptedPrivateKey, password);
                    console.log('Private key decryption successful');
                } catch (decryptError) {
                    console.error('Private key decryption error:', decryptError.message);
                    alert('Unable to decrypt private key. Please check password.');
                    return;
                }
            }

            sessionStorage.setItem('user', JSON.stringify(loginUser));
            sessionStorage.setItem('privateKey', finalPrivateKey);
            sessionStorage.setItem('accessToken', token || '');

            setUser(loginUser);
            setPrivateKey(finalPrivateKey);

            console.log('Login successfully:', { user: loginUser.email, role: loginUser.role });
            alert(res.data.message || 'Login successfully');
            navigate(loginUser.role === 'manager' ? '/manager' : '/dashboard');
        } catch (err) {
            console.error('Login error:', {
                message: err.message,
                response: err.response?.data,
                status: err.response?.status
            });
            let errorMessage = 'Login failed. Please check your email, password or role.';
            if (err.response?.status === 401) {
                errorMessage = 'Incorrect email, password or role.';
            } else if (err.response?.status === 400) {
                errorMessage = err.response.data.error || 'Invalid request.';
            } else if (err.message.includes('decrypt the private key')) {
                errorMessage = 'Unable to decrypt private key. Please check password.';
            }
            alert(errorMessage);
        }
    };

    const handleToggle = (selectedRole) => {
        setRole(selectedRole);
    };

    const isManager = role === 'manager';

    return (
        <>
            {showRegister ? (
                <Register role={role} onToggle={handleToggle} onBack={() => setShowRegister(false)} />
            ) : (
                <div
                    className={`container ${isManager ? 'manager-mode' : ''}`}
                    style={{
                        backgroundColor: isManager ? '#d3f9d8' : '#ffffff',
                        transition: 'background-color 0.5s ease',
                    }}
                >
                    <div className="left">
                        <img src={loginImage} alt="Login Illustration" />
                    </div>

                    <div
                        className="right"
                        style={{
                            backgroundColor: isManager ? '#4caf50' : '#ffffff',
                            color: isManager ? '#4caf50' : '#333',
                            transition: 'background-color 0.5s ease',
                        }}
                    >
                        <div className="top-bar">
                            <h2 style={{ color: isManager ? '#ffffff' : '#4caf50' }}>SafeVault Login</h2>
                            <RoleToggle onToggle={handleToggle} />
                        </div>

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
                            />
                        </div>
                        <div className="input-group">
                            <i className="fas fa-lock"></i>
                            <input
                                type="password"
                                placeholder="Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        <button
                            className="login-btn"
                            onClick={handleLogin}
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
                            LOGIN
                        </button>
                        <div className="login-footer">
                            <p>
                                Create your{' '}
                                <a href="/register" onClick={() => setShowRegister(true)}>
                                    Account →
                                </a>
                            </p>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}