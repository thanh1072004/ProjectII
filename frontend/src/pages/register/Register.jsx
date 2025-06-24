import './Register.css';
import RoleToggle from '../../role/RoleToggle';
import { useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import { generateECDHKeyPair, encryptPrivateKey } from '../../utils/cryptoUtils';

export default function Register() {
  const [role, setRole] = useState('employee');
  const isManager = role === 'manager';
  const handleToggle = (selectedRole) => {
    setRole(selectedRole);
  };
  const navigate = useNavigate();

  // for register
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('');
  const [rePassword, setRePassword] = useState('')

  const handleRegister = async(e) => {
    e.preventDefault();
    
    // Validate password match
    if (password !== rePassword){
        alert('Please re-enter your password');
        return;
    }

    // Validate email
    if (!email) {
        alert('Email is required');
        return;
    }

    try {
        // Generate key pair
        const {publicKey, privateKey} = await generateECDHKeyPair();

        const encryptedPrivateKey = await encryptPrivateKey(privateKey, password); // Added await

        console.log('Generated keys:', {
            publicKeyLength: publicKey.length,
            privateKeyLength: privateKey.length,
            encryptedPrivateKeyType: typeof encryptedPrivateKey
        });
        // Register user with public key
        const res = await axios.post(
            `${import.meta.env.VITE_API_URL}/auth/register`, 
            {
                role,
                email,
                password,
                publicKey,
                encryptedPrivateKey
            }
        );

        alert(res.data.message);
        navigate('/login');
    } catch (err) {
        const errorMessage = err.response?.data?.error || 'Registration failed';
        alert(errorMessage);
        console.error('Registration error:', err);
    }
  }
  
  return (
    <div
      className={`register-container ${isManager ? 'manager-mode' : ''}`}
      style={{
        backgroundColor: '#d3f9d8',
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
        <h2 style={{ color: isManager ? '#ffffff' : '#4caf50' }}>Create Account</h2>
        <RoleToggle onToggle={handleToggle} />

       
        <div className="input-group">
          <i className="fas fa-envelope"></i>
          <input type="email" 
            placeholder="Email" 
            value={email} 
            onChange={e => setEmail(e.target.value)}/>
        </div>
        <div className="input-group">
          <i className="fas fa-lock"></i>
          <input type="password" 
            placeholder="Password" 
            value={password}
            onChange={e => setPassword(e.target.value)}/>
        </div>
        <div className="input-group">
          <i className="fas fa-lock"></i>
          <input type="password" 
            placeholder="Confirm Password"
            value={rePassword} 
            onChange={e => setRePassword(e.target.value)}/>
        </div>
        <button
          className="register-btn"
          onClick={handleRegister}
          style={
            isManager
              ? {
                  backgroundColor: '#ffffff',
                  color: '#4caf50',
                  border: '2px solid #ffffff',
                }
              : {}
          }
        >
          CREATE ACCOUNT
        </button>

        <div className="register-footer">
          <p>
            Already have an account?{' '}
            <a href="/login" >
              Back to Login
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
