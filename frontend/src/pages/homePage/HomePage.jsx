import React, { useContext, useState, useEffect, useCallback } from 'react';
import {
    FaUser,
    FaBell,
    FaHome,
    FaKey,
    FaBuilding,
    FaPaperPlane,
    FaShareSquare,
    FaSignOutAlt,
    FaSearch,
    FaEye,
    FaEyeSlash,
    FaEdit,
    FaTrash,
} from 'react-icons/fa';
import './HomePage.css';
import CreatePassword from './createPassword/CreatePassword';
import CompanyMembers from './company/CompanyMembers';
import SharePassword from './sharePassword/SharePassword';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import ChatBox from './chatbox/ChatBox';
import { decryptWithPrivateKey, testKeyPair, decryptSharedPassword } from '../../utils/cryptoUtils';

export default function HomePage() {
    const { user, setUser, privateKey, setPrivateKey } = useContext(UserContext);
    const [activePage, setActivePage] = useState('home');
    const [visibleIndex, setVisibleIndex] = useState(null);
    const [passwords, setPasswords] = useState([]);
    const [decryptedPasswords, setDecryptedPasswords] = useState({});
    const [loading, setLoading] = useState(false);
    const [keyPairValid, setKeyPairValid] = useState(null);
    const [isInitialized, setIsInitialized] = useState(false);
    const [error, setError] = useState(null);
    const [notifications, setNotifications] = useState([]);
    const [showNotifications, setShowNotifications] = useState(false);
    const [editingPassword, setEditingPassword] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        const initializeSession = () => {
            const storedUser = sessionStorage.getItem('user');
            const storedPrivateKey = sessionStorage.getItem('privateKey');
            const storedToken = sessionStorage.getItem('accessToken');

            if (storedUser && storedPrivateKey && storedToken) {
                try {
                    const userData = JSON.parse(storedUser);
                    if (!user) {
                        setUser(userData);
                    }
                    if (!privateKey) {
                        setPrivateKey(storedPrivateKey);
                    }
                    console.log('Session restored for user:', userData.email, 'Role:', userData.role);
                    setIsInitialized(true);
                } catch (error) {
                    console.error('Failed to restore user session:', error);
                    sessionStorage.removeItem('user');
                    sessionStorage.removeItem('privateKey');
                    sessionStorage.removeItem('accessToken');
                    navigate('/login');
                }
            } else {
                console.log('No stored session found, redirecting to login');
                navigate('/login');
            }
        };

        if (!user || !privateKey) {
            initializeSession();
        } else {
            setIsInitialized(true);
        }
    }, [user, privateKey, setUser, setPrivateKey, navigate]);

    useEffect(() => {
        if (isInitialized && user && privateKey) {
            fetchPasswords();
            validateKeyPair();
            fetchNotifications();
        }
    }, [isInitialized, user, privateKey]);

    const fetchNotifications = useCallback(async () => {
        try {
            console.log('Fetching notifications from:', `${import.meta.env.VITE_API_URL}/employee/notifications`);
            const response = await axios.get(`${import.meta.env.VITE_API_URL}/employee/notifications`, {
                withCredentials: true
            });
            console.log('Notifications response:', response.data);
            setNotifications(response.data.notifications || []);
        } catch (error) {
            console.error('Error fetching notifications:', error.response?.data || error.message);
            setNotifications([]);
        }
    }, []);

    const markNotificationAsRead = async (notificationId) => {
        try {
            console.log('Marking notification as read:', notificationId);
            await axios.post(
                `${import.meta.env.VITE_API_URL}/employee/notifications/${notificationId}/read`,
                {},
                { withCredentials: true }
            );
            setNotifications(prev =>
                prev.map(notification =>
                    notification.id === notificationId
                        ? { ...notification, read: true }
                        : notification
                )
            );
            console.log('Notification marked as read locally:', notificationId);
        } catch (error) {
            console.error('Error marking notification as read:', error.response?.data || error.message);
        }
    };

    const toggleNotifications = () => {
        setShowNotifications(!showNotifications);
    };

    const validateKeyPair = useCallback(async () => {
        try {
            const currentPrivateKey = privateKey || sessionStorage.getItem('privateKey');

            if (!currentPrivateKey) {
                console.warn('No private key found in sessionStorage or UserContext');
                setKeyPairValid(false);
                navigate('/login');
                return;
            }

            if (!user?.publicKey) {
                console.warn('No public key found in user data:', user);
                setKeyPairValid(false);
                return;
            }

            console.log('Validating key pair for user:', user.email);
            const isValid = await testKeyPair(user.publicKey, currentPrivateKey);
            console.log('Key pair validation result:', isValid);

            setKeyPairValid(isValid);

            if (!isValid) {
                console.error('Key pair validation failed. Private key may not match public key.');
                alert('Your encryption keys are invalid. Please log in again.');
            }
        } catch (error) {
            console.error('Error validating key pair:', {
                message: error.message,
                stack: error.stack
            });
            setKeyPairValid(false);
        }
    }, [user, privateKey, navigate]);

    const handleLogout = async () => {
        try {
            console.log('Sending logout request');
            const res = await axios.post(
                `${import.meta.env.VITE_API_URL}/auth/logout`,
                {},
                { withCredentials: true }
            );

            setUser(null);
            setPrivateKey(null);
            sessionStorage.removeItem('user');
            sessionStorage.removeItem('privateKey');
            sessionStorage.removeItem('accessToken');
            alert(res.data.message);
            navigate('/login');
        } catch (err) {
            console.error('Logout failed:', err.response?.data || err.message);
            setUser(null);
            setPrivateKey(null);
            sessionStorage.removeItem('user');
            sessionStorage.removeItem('privateKey');
            sessionStorage.removeItem('accessToken');
            alert(err.response?.data?.error || 'Logout failed');
            navigate('/login');
        }
    };

    const fetchPasswords = useCallback(async (retryCount = 0) => {
        try {
            setLoading(true);
            setError(null);

            if (!user || !user.role) {
                console.error('No user or role found in UserContext');
                setError('Please log in again');
                navigate('/login');
                return;
            }

            const endpoint = user.role === 'manager' 
                ? `${import.meta.env.VITE_API_URL}/manager/passwords` 
                : `${import.meta.env.VITE_API_URL}/employee/all-passwords`;
            console.log('Fetching passwords from:', endpoint);
            console.log('User role:', user.role);

            const response = await axios.get(endpoint, {
                withCredentials: true
            });

            console.log('API response:', response.data);
            console.log('Personal passwords:', response.data.personalPasswords);
            console.log('Shared passwords:', response.data.sharedPasswords);

            const personalPasswords = (response.data.personalPasswords || []).map(pwd => ({
                ...pwd,
                id: pwd._id || pwd.id,
                owner: 'Me'
            }));

            const sharedPasswords = (response.data.sharedPasswords || []).map(pwd => ({
                ...pwd,
                id: pwd._id || pwd.id,
                owner: pwd.sharedBy
            }));

            console.log('Processed personal passwords:', personalPasswords);
            console.log('Processed shared passwords:', sharedPasswords);

            const allPasswords = [...personalPasswords, ...sharedPasswords];
            setPasswords(allPasswords);
        } catch (error) {
            console.error('Error fetching passwords:', {
                message: error.message,
                response: error.response?.data,
                status: error.response?.status
            });
            if (error.response?.status === 401 && retryCount < 3) {
                console.log(`Retrying fetch passwords, attempt ${retryCount + 1}`);
                setTimeout(() => fetchPasswords(retryCount + 1), 1000);
                return;
            }
            let errorMessage = 'Failed to fetch passwords';
            if (error.response?.status === 404) {
                errorMessage = 'Password endpoint not found. Please check server configuration.';
            } else if (error.response?.status === 401) {
                errorMessage = 'Session expired. Please log in again.';
                sessionStorage.removeItem('user');
                sessionStorage.removeItem('privateKey');
                sessionStorage.removeItem('accessToken');
                setUser(null);
                setPrivateKey(null);
                navigate('/login');
            } else if (error.response?.status === 403) {
                errorMessage = 'Access denied: Required role not met.';
            } else {
                errorMessage += `: ${error.response?.data?.error || error.message}`;
            }
            setError(errorMessage);
            alert(errorMessage);
        } finally {
            setLoading(false);
        }
    }, [user, navigate, setUser, setPrivateKey]);

    const handleViewPassword = async (id) => {
        try {
            if (visibleIndex === id) {
                setVisibleIndex(null);
                return;
            }

            const currentPrivateKey = privateKey || sessionStorage.getItem('privateKey');
            if (!currentPrivateKey) {
                throw new Error('No private key found. Please log in again.');
            }

            if (keyPairValid === false) {
                throw new Error('Encryption keys are invalid. Please log in again.');
            }

            const password = passwords.find(p => p.id === id);
            if (!password) {
                throw new Error('Password not found');
            }

            if (!password.encrypted_password) {
                throw new Error('Encrypted password data not found');
            }

            let encryptedData;
            try {
                encryptedData = typeof password.encrypted_password === 'string'
                    ? JSON.parse(password.encrypted_password)
                    : password.encrypted_password;
                if (!encryptedData.ephemeralPublicKey || !encryptedData.iv || !encryptedData.ciphertext || !encryptedData.authTag) {
                    throw new Error('Invalid encrypted data: Missing one or more of ephemeralPublicKey, iv, ciphertext, authTag');
                }
            } catch (parseError) {
                console.error('Error parsing encrypted data:', {
                    id,
                    encrypted_password: password.encrypted_password,
                    error: parseError.message
                });
                throw new Error('Invalid encrypted data: Not valid JSON');
            }

            console.log('Attempting to decrypt password:', {
                id,
                name: password.name,
                owner: password.owner,
                sharedBy: password.sharedBy,
                encrypted_password: JSON.stringify(encryptedData, null, 2)
            });

            let decrypted;
            try {
                if (password.owner !== 'Me' && password.sharedBy) {
                    decrypted = await decryptSharedPassword(password.encrypted_password, currentPrivateKey);
                } else {
                    decrypted = await decryptWithPrivateKey(password.encrypted_password, currentPrivateKey);
                }
            } catch (decryptError) {
                console.error('Decryption error:', {
                    id,
                    name: password.name,
                    owner: password.owner,
                    sharedBy: password.sharedBy,
                    encrypted_password: JSON.stringify(encryptedData, null, 2),
                    error: decryptError.message,
                    stack: decryptError.stack
                });
                throw new Error(`Decryption failed: ${decryptError.message}`);
            }

            console.log('Decrypted password:', decrypted);
            setDecryptedPasswords(prev => ({
                ...prev,
                [id]: String(decrypted)
            }));
            setVisibleIndex(id);
        } catch (error) {
            console.error('Password decryption failed:', {
                passwordId: id,
                error: error.message,
                stack: error.stack
            });

            let userMessage = 'Failed to decrypt password';
            if (error.message.includes('No private key found')) {
                userMessage = 'Authentication session expired. Please log in again.';
                sessionStorage.removeItem('user');
                sessionStorage.removeItem('privateKey');
                sessionStorage.removeItem('accessToken');
                setUser(null);
                setPrivateKey(null);
                navigate('/login');
            } else if (error.message.includes('private key does not match') || error.message.includes('corrupted data')) {
                userMessage = 'Cannot decrypt password. Keys may not match or data may be corrupted.';
            } else if (error.message.includes('Not valid JSON')) {
                userMessage = 'Password data is corrupted.';
            } else {
                userMessage += `: ${error.message}`;
            }

            alert(userMessage);
        }
    };

    const handleDeletePassword = async (id) => {
        if (!window.confirm('Are you sure you want to delete this password?')) {
            return;
        }

        try {
            console.log('Deleting password:', id);
            await axios.delete(`${import.meta.env.VITE_API_URL}/employee/passwords/${id}`, {
                withCredentials: true
            });

            // Cập nhật danh sách mật khẩu bằng cách gọi lại fetchPasswords
            await fetchPasswords();
            console.log('Password deleted successfully:', id);

            // Xóa mật khẩu đã giải mã (nếu có)
            setDecryptedPasswords(prev => {
                const newDecrypted = { ...prev };
                delete newDecrypted[id];
                return newDecrypted;
            });

            // Nếu mật khẩu đang hiển thị, xóa trạng thái hiển thị
            if (visibleIndex === id) {
                setVisibleIndex(null);
            }

            alert('Password deleted successfully');
        } catch (error) {
            console.error('Error deleting password:', error.response?.data || error.message);
            let errorMessage = 'Failed to delete password';
            if (error.response?.status === 404) {
                errorMessage = 'Password not found';
            } else if (error.response?.status === 401) {
                errorMessage = 'Session expired. Please log in again.';
                sessionStorage.removeItem('user');
                sessionStorage.removeItem('privateKey');
                sessionStorage.removeItem('accessToken');
                setUser(null);
                setPrivateKey(null);
                navigate('/login');
            } else {
                errorMessage += `: ${error.response?.data?.error || error.message}`;
            }
            setError(errorMessage);
            alert(errorMessage);
        }
    };

    const handleEditPassword = async (id) => {
        try {
            const password = passwords.find(p => p.id === id);
            if (!password) {
                throw new Error('Password not found');
            }

            if (password.owner !== 'Me') {
                throw new Error('You can only edit passwords you own');
            }

            const currentPrivateKey = privateKey || sessionStorage.getItem('privateKey');
            if (!currentPrivateKey) {
                throw new Error('No private key found. Please log in again.');
            }

            if (!password.encrypted_password) {
                throw new Error('Encrypted password data not found');
            }

            let encryptedData;
            try {
                encryptedData = typeof password.encrypted_password === 'string'
                    ? JSON.parse(password.encrypted_password)
                    : password.encrypted_password;
                if (!encryptedData.ephemeralPublicKey || !encryptedData.iv || !encryptedData.ciphertext || !encryptedData.authTag) {
                    throw new Error('Invalid encrypted data: Missing one or more of ephemeralPublicKey, iv, ciphertext, authTag');
                }
            } catch (parseError) {
                console.error('Error parsing encrypted data:', {
                    id,
                    encrypted_password: password.encrypted_password,
                    error: parseError.message
                });
                throw new Error('Invalid encrypted data: Not valid JSON');
            }

            let decrypted;
            try {
                decrypted = await decryptWithPrivateKey(password.encrypted_password, currentPrivateKey);
            } catch (decryptError) {
                console.error('Decryption error:', {
                    id,
                    name: password.name,
                    error: decryptError.message
                });
                throw new Error(`Decryption failed: ${decryptError.message}`);
            }

            setEditingPassword({
                id: password.id,
                name: password.name,
                website: password.website,
                username: password.username,
                decryptedPassword: String(decrypted)
            });
            setActivePage('createPassword');
        } catch (error) {
            console.error('Error preparing password for edit:', error);
            alert(error.message || 'Failed to prepare password for editing');
        }
    };

    const handlePasswordUpdated = () => {
        setEditingPassword(null);
        setActivePage('home');
        fetchPasswords();
    };

    const renderPasswordTable = () => {
        console.log('Rendering password table with passwords:', passwords);
        return (
            <div className="homepage-main-body">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <h2 className="homepage-section-title">YOUR PASSWORD TABLE</h2>
                    <button onClick={fetchPasswords} className="refresh-button" title="Refresh passwords">
                        Refresh
                    </button>
                </div>
                {error && <div className="error-message" style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
                <table className="homepage-password-table">
                    <thead>
                        <tr>
                            <th>Order</th>
                            <th>Name</th>
                            <th>Website</th>
                            <th>Username</th>
                            <th>Password</th>
                            <th>Owner</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {passwords.length > 0 ? (
                            passwords.map((item, idx) => (
                                <tr key={item.id}>
                                    <td>{idx + 1}</td>
                                    <td>{item.name}</td>
                                    <td>{item.website || '-'}</td>
                                    <td>{item.username}</td>
                                    <td>
                                        {visibleIndex === item.id
                                            ? (decryptedPasswords[item.id] || 'Decrypting...')
                                            : '••••••••'}
                                    </td>
                                    <td>
                                        <span className={item.owner === 'Me' ? 'owner-me' : 'owner-shared'}>
                                            {item.owner}
                                        </span>
                                    </td>
                                    <td className="action-buttons">
                                        <button
                                            className="btn-view"
                                            onClick={() => handleViewPassword(item.id)}
                                            disabled={keyPairValid === false}
                                            title={keyPairValid === false ? 'Keys invalid - please log in again' : 'View password'}
                                        >
                                            {visibleIndex === item.id ? <FaEyeSlash /> : <FaEye />}
                                        </button>
                                        {item.owner === 'Me' && (
                                            <button
                                                className="btn-edit"
                                                onClick={() => handleEditPassword(item.id)}
                                                title="Edit password"
                                            >
                                                <FaEdit />
                                            </button>
                                        )}
                                        <button
                                            className="btn-delete"
                                            onClick={() => handleDeletePassword(item.id)}
                                            title="Delete password"
                                        >
                                            <FaTrash />
                                        </button>
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan={7} style={{ textAlign: 'center', color: '#888' }}>
                                    {loading ? 'Loading passwords...' : 'No passwords found.'}
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        );
    };

    const renderMainContent = () => {
        switch (activePage) {
            case 'createPassword':
                return <CreatePassword onPasswordAdded={fetchPasswords} editingPassword={editingPassword} onPasswordUpdated={handlePasswordUpdated} />;
            case 'company':
                return <CompanyMembers />;
            case 'sharePassword':
                return <SharePassword />;
            case 'groupChat':
                return <ChatBox />;
            default:
                return renderPasswordTable();
        }
    };

    if (!isInitialized || !user) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100vh',
                fontSize: '18px',
                color: '#666'
            }}>
                Loading...
            </div>
        );
    }

    const unreadNotificationsCount = notifications.filter(n => !n.read).length;

    return (
        <div className="homepage-container">
            <div className="homepage-sidebar">
                <div>
                    <div className="homepage-sidebar-header">SafeVault</div>
                    <div className="homepage-sidebar-menu">
                        <div className="homepage-sidebar-item" onClick={() => setActivePage('home')}><FaHome /> Home</div>
                        <div className="homepage-sidebar-item" onClick={() => setActivePage('createPassword')}><FaKey /> Create Password</div>
                        <div className="homepage-sidebar-item" onClick={() => setActivePage('company')}><FaBuilding /> Your Company</div>
                        <div className="homepage-sidebar-item" onClick={() => setActivePage('sharePassword')}><FaPaperPlane /> Share Password</div>
                        <div className="homepage-sidebar-item" onClick={() => setActivePage('groupChat')}><FaShareSquare /> Group Chat</div>
                    </div>
                    <div className="homepage-sidebar-divider"></div>
                </div>
                <div className="homepage-logout" onClick={handleLogout}><FaSignOutAlt /> Log Out</div>
            </div>

            <div className="homepage-main-content">
                <div className="homepage-top-bar">
                    <div className="homepage-search-box">
                        <FaSearch className="homepage-search-icon" />
                        <input
                            type="text"
                            placeholder="Search your colleague"
                            className="homepage-search-input"
                        />
                    </div>
                    <div className="homepage-icon-button"><FaUser size={20} /></div>
                    <div className="homepage-icon-button notification-container">
                        <FaBell size={20} onClick={toggleNotifications} />
                        {unreadNotificationsCount > 0 && (
                            <span className="notification-badge">{unreadNotificationsCount}</span>
                        )}
                        {showNotifications && (
                            <div className="notification-dropdown">
                                <h3>Notifications</h3>
                                {notifications.length > 0 ? (
                                    <ul>
                                        {notifications.map(notification => (
                                            <li
                                                key={notification.id}
                                                className={notification.read ? 'read' : 'unread'}
                                                onClick={() => markNotificationAsRead(notification.id)}
                                            >
                                                {notification.message}
                                                <br />
                                                <small>{new Date(notification.createdAt).toLocaleString()}</small>
                                            </li>
                                        ))}
                                    </ul>
                                ) : (
                                    <p>No notifications found.</p>
                                )}
                            </div>
                        )}
                    </div>
                </div>
                {renderMainContent()}
            </div>
        </div>
    );
}