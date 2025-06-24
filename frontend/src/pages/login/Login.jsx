import './Login.css';
import loginImage from '../../assets/login-illustration.png';
import RoleToggle from '../../role/RoleToggle';
import Register from '../register/Register';
import { useState, useContext } from 'react';
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import { UserContext } from '../../context/UserContext';
import { decryptPrivateKey } from '../../utils/cryptoUtils';

export default function Login() {
    const { setUser, setPrivateKey } = useContext(UserContext); 
    const [role, setRole] = useState('employee');
    const [showRegister, setShowRegister] = useState(false);

    // for login
    const [code, setCode] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const navigate = useNavigate()

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            if (isManager && code !== import.meta.env.VITE_SECRET_CODE) {
                alert('The secret code is not correct');
                return;
            }
            
            const res = await axios.post('http://localhost:3000/api/auth/login', { email, password }, { withCredentials: true });

            const loginUser = res.data.user;
            const encryptedPrivateKey = loginUser.encryptedPrivateKey;
            
            if (!encryptedPrivateKey) {
                alert('Encrypted private key missing from user data');
                return;
            }

            const privateKey = await decryptPrivateKey(encryptedPrivateKey, password);
			
			sessionStorage.setItem('privateKey', privateKey);
        	sessionStorage.setItem('user', JSON.stringify(loginUser));
            
            setUser(loginUser);
            setPrivateKey(privateKey); 
            
            alert(res.data.message);
            navigate('/dashboard');
            
        } catch (err) {
            console.error('Login error:', err);
            alert(err.response?.data?.error || 'Login failed');
        }
    }


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
							<input type="text"
								placeholder="Company Secret Code"
								value={code}
								onChange={e => setCode(e.target.value)} />
						</div>
						<div className="input-group">
							<i className="fas fa-envelope"></i>
							<input type="email"
								placeholder="Email"
								value={email}
								onChange={e => setEmail(e.target.value)} />
						</div>
						<div className="input-group">
							<i className="fas fa-lock"></i>
							<input type="password"
								placeholder="Password"
								value={password}
								onChange={e => setPassword(e.target.value)} />
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
								Create your <a href="/register" onClick={() => setShowRegister(true)}>Account →</a>
							</p>
						</div>
					</div>
				</div>
			)}
		</>
	);
}
