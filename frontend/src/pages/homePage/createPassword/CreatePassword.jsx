import React, { useState, useContext, useEffect } from 'react';
import './CreatePassword.css';
import { FaEdit, FaLock, FaGlobe, FaUser } from 'react-icons/fa';
import { UserContext } from '../../../context/UserContext';
import axios from 'axios';
import { encryptWithPublicKey, generateTempAESKey, encryptWithAES } from '../../../utils/cryptoUtils';

export default function CreatePassword({ onPasswordAdded, editingPassword, onPasswordUpdated }) {
    const { user } = useContext(UserContext);
    const [formData, setFormData] = useState({
        name: '',
        website: '',
        username: '',
        password: '',
        confirmPassword: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        if (editingPassword) {
            setFormData({
                name: editingPassword.name || '',
                website: editingPassword.website || '',
                username: editingPassword.username || '',
                password: editingPassword.decryptedPassword || '',
                confirmPassword: editingPassword.decryptedPassword || ''
            });
        } else {
            setFormData({
                name: '',
                website: '',
                username: '',
                password: '',
                confirmPassword: ''
            });
        }
    }, [editingPassword]);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (isSubmitting) {
            console.log('Submission already in progress, ignoring');
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            alert('Please confirm that password you re-entered is correct!');
            return;
        }

        setIsSubmitting(true);

        try {
            if (!user || !user.publicKey) {
                throw new Error('Public key not found. Please log in again.');
            }

            if (!user.role) {
                throw new Error('User role not defined. Please log in again.');
            }

            console.log('User role:', user.role);

            // Mã hóa mật khẩu bằng publicKey của user
            const encrypted_password = await encryptWithPublicKey(
                formData.password,
                user.publicKey
            );
            console.log('Generated encrypted_password:', encrypted_password);

            let payload = {
                name: formData.name,
                website: formData.website,
                username: formData.username,
                encrypted_password
            };

            // Nếu là manager, thêm plainPassword mã hóa bằng AES tạm thời
            if (user.role === 'manager') {
                try {
                    const tempAESKey = await generateTempAESKey();
                    const encryptedPlainPassword = await encryptWithAES(formData.password, tempAESKey);
                    // Kiểm tra định dạng
                    if (!tempAESKey || typeof tempAESKey !== 'string') {
                        throw new Error('Invalid tempAESKey format');
                    }
                    try {
                        JSON.parse(encryptedPlainPassword);
                    } catch {
                        throw new Error('Invalid encryptedPlainPassword format');
                    }
                    console.log('Generated tempAESKey:', tempAESKey);
                    console.log('Generated encryptedPlainPassword:', encryptedPlainPassword);
                    payload = {
                        ...payload,
                        tempAESKey,
                        encryptedPlainPassword
                    };
                } catch (aesError) {
                    console.error('Failed to generate AES key or encrypt plain password:', aesError);
                    throw new Error(`AES encryption error: ${aesError.message}`);
                }
            }

            console.log('Sending to API:', payload);

            let res;
            if (editingPassword) {
                // Chế độ chỉnh sửa
                const apiEndpoint = user.role === 'manager'
                    ? `${import.meta.env.VITE_API_URL}/manager/passwords/${editingPassword.id}`
                    : `${import.meta.env.VITE_API_URL}/employee/passwords/${editingPassword.id}`;
                res = await axios.put(
                    apiEndpoint,
                    payload,
                    { withCredentials: true }
                );
                console.log('Password update response:', res.data);
                alert(res.data.message);
                if (onPasswordUpdated) {
                    console.log('Calling onPasswordUpdated');
                    onPasswordUpdated();
                }
            } else {
                // Chế độ tạo mới
                const apiEndpoint = user.role === 'manager'
                    ? `${import.meta.env.VITE_API_URL}/manager/add-password`
                    : `${import.meta.env.VITE_API_URL}/employee/add-password`;
                res = await axios.post(
                    apiEndpoint,
                    payload,
                    { withCredentials: true }
                );
                console.log('Password creation response:', res.data);
                alert(res.data.message);
                if (onPasswordAdded) {
                    console.log('Calling onPasswordAdded');
                    onPasswordAdded();
                }
            }

            // Reset form
            setFormData({
                name: '',
                website: '',
                username: '',
                password: '',
                confirmPassword: ''
            });
        } catch (err) {
            const errorMessage = err.response?.data?.error || err.message || 'Failed to process password';
            console.error('Error processing password:', err);
            alert(errorMessage);
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="create-password-container">
            <h2 className="create-password-title">
                {editingPassword ? 'EDIT PASSWORD' : 'CREATE NEW PASSWORD'}
            </h2>
            <form className="create-password-form" onSubmit={handleSubmit}>
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
                <button type="submit" className="create-password-button" disabled={isSubmitting}>
                    {editingPassword ? 'Update Password' : 'Create Password'}
                </button>
            </form>
        </div>
    );
}