import React, { useState, useContext } from 'react';
import './CreatePassword.css';
import { FaEdit, FaLock, FaGlobe, FaUser } from 'react-icons/fa';
import { UserContext } from '../../../context/UserContext';
import axios from 'axios';
import { encryptWithPublicKey } from '../../../utils/cryptoUtils'; 

export default function CreatePassword() {
  const { user } = useContext(UserContext);
  const [formData, setFormData] = useState({
    name: '',
    website: '',
    username: '',
    password: '',
    confirmPassword: ''
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleAddPassword = async (e) => {
    e.preventDefault();
    
    if (formData.password !== formData.confirmPassword) {
      alert('Please confirm that password you re-entered is correct!');
      return;
    }

    try {
      // Get user's public key
      if (!user || !user.publicKey) {
        throw new Error('Public key not found. Please log in again.');
      }

      // Encrypt password with user's public key
      const encrypted_password = await encryptWithPublicKey(
        formData.password,
        user.publicKey
      );

      const res = await axios.post(
        `${import.meta.env.VITE_API_URL}/employee/add-password`,
        {
          name: formData.name,
          website: formData.website,
          username: formData.username,
          encrypted_password
        },
        { withCredentials: true }
      );

      alert(res.data.message);
      // Reset form
      setFormData({
        name: '',
        website: '',
        username: '',
        password: '',
        confirmPassword: ''
      });
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.message || 'Failed to create password';
      alert(errorMessage);
      console.error('Error creating password:', err);
    }
  };

  return (
    <div className="create-password-container">
      <h2 className="create-password-title">CREATE NEW PASSWORD</h2>
      <form className="create-password-form" onSubmit={handleAddPassword}>
        <div className="input-group">
          <FaEdit className="input-icon" />
          <input
            type="text"
            name="name"
            placeholder="Name/Title"
            value={formData.name}
            onChange={handleChange}
            required
          />
        </div>
        <div className="input-group">
          <FaGlobe className="input-icon" />
          <input
            type="text"
            name="website"
            placeholder="Website (optional)"
            value={formData.website}
            onChange={handleChange}
          />
        </div>
        <div className="input-group">
          <FaUser className="input-icon" />
          <input
            type="text"
            name="username"
            placeholder="Username"
            value={formData.username}
            onChange={handleChange}
            required
          />
        </div>
        <div className="input-group">
          <FaLock className="input-icon" />
          <input
            type="password"
            name="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleChange}
            required
          />
        </div>
        <div className="input-group">
          <FaLock className="input-icon" />
          <input
            type="password"
            name="confirmPassword"
            placeholder="Confirm Password"
            value={formData.confirmPassword}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit" className="create-password-button">
          Create Password
        </button>
      </form>
    </div>
  );
}
