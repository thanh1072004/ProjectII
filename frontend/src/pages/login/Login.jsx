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
                console.error('Mã bí mật không đúng:', code);
                alert('Mã bí mật không đúng');
                return;
            }

            console.log('Gửi yêu cầu đăng nhập:', { email, role, password: '****' });
            const res = await axios.post(
                `${import.meta.env.VITE_API_URL}/auth/login`,
                { email, password, role }, // Thêm role vào body
                { withCredentials: true }
            );

            console.log('Phản hồi từ API đăng nhập:', res.data);

            const { user: loginUser, privateKey, token } = res.data;
            if (!loginUser) {
                console.error('Phản hồi API thiếu thông tin người dùng');
                alert('Dữ liệu người dùng không hợp lệ từ máy chủ');
                return;
            }

            if (!privateKey && !loginUser.encryptedPrivateKey) {
                console.error('Thiếu encryptedPrivateKey hoặc privateKey trong phản hồi');
                alert('Khóa riêng mã hóa không có trong dữ liệu người dùng');
                return;
            }

            // Nếu backend không trả về privateKey đã giải mã, giải mã ở frontend
            let finalPrivateKey = privateKey;
            if (!privateKey && loginUser.encryptedPrivateKey) {
                console.log('Đang giải mã khóa riêng với encryptedPrivateKey:', loginUser.encryptedPrivateKey);
                try {
                    finalPrivateKey = await decryptPrivateKey(loginUser.encryptedPrivateKey, password);
                    console.log('Giải mã khóa riêng thành công');
                } catch (decryptError) {
                    console.error('Lỗi giải mã khóa riêng:', decryptError.message);
                    alert('Không thể giải mã khóa riêng. Vui lòng kiểm tra mật khẩu.');
                    return;
                }
            }

            // Lưu thông tin vào sessionStorage
            sessionStorage.setItem('user', JSON.stringify(loginUser));
            sessionStorage.setItem('privateKey', finalPrivateKey);
            sessionStorage.setItem('accessToken', token || '');

            // Cập nhật context
            setUser(loginUser);
            setPrivateKey(finalPrivateKey);

            console.log('Đăng nhập thành công:', { user: loginUser.email, role: loginUser.role });
            alert(res.data.message || 'Đăng nhập thành công');
            navigate(loginUser.role === 'manager' ? '/manager' : '/dashboard');
        } catch (err) {
            console.error('Lỗi đăng nhập:', {
                message: err.message,
                response: err.response?.data,
                status: err.response?.status
            });
            let errorMessage = 'Đăng nhập thất bại. Vui lòng kiểm tra email, mật khẩu hoặc vai trò.';
            if (err.response?.status === 401) {
                errorMessage = 'Email, mật khẩu hoặc vai trò không đúng.';
            } else if (err.response?.status === 400) {
                errorMessage = err.response.data.error || 'Yêu cầu không hợp lệ.';
            } else if (err.message.includes('giải mã khóa riêng')) {
                errorMessage = 'Không thể giải mã khóa riêng. Vui lòng kiểm tra mật khẩu.';
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