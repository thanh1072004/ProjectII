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
    FaEdit,
    FaTrash,
} from 'react-icons/fa';
import './HomePage.css';
import CreatePassword from './createPassword/CreatePassword';
import CompanyMembers from './company/CompanyMembers';
import SharePassword from './sharePassword/SharePassword';
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
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
    const navigate = useNavigate();

    // First useEffect: Restore session data
    useEffect(() => {
        const initializeSession = () => {
            const storedUser = sessionStorage.getItem('user');
            const storedPrivateKey = sessionStorage.getItem('privateKey');

            if (storedUser && storedPrivateKey) {
                try {
                    const userData = JSON.parse(storedUser);
                    if (!user) {
                        setUser(userData);
                    }
                    if (!privateKey) {
                        setPrivateKey(storedPrivateKey);
                    }
                    setIsInitialized(true);
                } catch (error) {
                    console.error('Failed to restore user session:', error);
                    sessionStorage.removeItem('user');
                    sessionStorage.removeItem('privateKey');
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
    }, []);

    useEffect(() => {
        if (isInitialized && user && privateKey) {
            fetchPasswords();
            validateKeyPair();
        }
    }, [isInitialized, user, privateKey]);

    const validateKeyPair = useCallback(async () => {
        try {
            const currentPrivateKey = privateKey || sessionStorage.getItem('privateKey');

            if (!currentPrivateKey) {
                console.warn('Missing private key');
                setKeyPairValid(false);
                navigate('/login');
                return;
            }

            if (!user?.publicKey) {
                console.warn('Missing public key from user data');
                setKeyPairValid(false);
                return;
            }

            const isValid = await testKeyPair(user.publicKey, currentPrivateKey);
            setKeyPairValid(isValid);

            if (!isValid) {
                console.error('Key pair validation failed');
                alert('Your encryption keys appear to be invalid. You may need to log in again.');
            }
        } catch (error) {
            console.error('Key pair validation error:', error);
            setKeyPairValid(false);
        }
    }, [user?.publicKey, privateKey, navigate]);

    const handleLogout = async (e) => {
        try {
            const res = await axios.post('http://localhost:3000/api/auth/logout', {}, { withCredentials: true });

            setUser(null);
            setPrivateKey(null);

            sessionStorage.removeItem('user');
            sessionStorage.removeItem('privateKey');

            alert(res.data.message);
            navigate('/login');
        } catch (err) {
            setUser(null);
            setPrivateKey(null);
            sessionStorage.removeItem('user');
            sessionStorage.removeItem('privateKey');

            alert(err.response?.data?.error || 'Logout failed');
            navigate('/login');
        }
    };

    const fetchPasswords = useCallback(async () => {
        try {
            setLoading(true);
            const response = await axios.get(
                `${import.meta.env.VITE_API_URL}/employee/all-passwords`,
                { withCredentials: true }
            );

            const personalPasswords = response.data.personalPasswords.map(pwd => ({
                ...pwd,
                owner: 'Me'
            }));

            const sharedPasswords = response.data.sharedPasswords.map(pwd => ({
                ...pwd,
                owner: pwd.sharedBy
            }));
            console.log(sharedPasswords)

            const allPasswords = [...personalPasswords, ...sharedPasswords];
            setPasswords(allPasswords);

        } catch (error) {
            console.error('Failed to fetch passwords:', error);

            if (error.response?.status === 401) {
                sessionStorage.removeItem('user');
                sessionStorage.removeItem('privateKey');
                setUser(null);
                setPrivateKey(null);
                navigate('/login');
                return;
            }

            alert('Failed to fetch passwords: ' + (error.response?.data?.error || error.message));
        } finally {
            setLoading(false);
        }
    }, [navigate, setUser, setPrivateKey]);

    const handleViewPassword = async (id) => {
        try {
            // If already decrypted, just toggle visibility
            if (decryptedPasswords[id]) {
                setVisibleIndex(visibleIndex === id ? null : id);
                return;
            }

            // Get privateKey from context first, then sessionStorage as fallback
            const currentPrivateKey = privateKey || sessionStorage.getItem('privateKey');

            if (!currentPrivateKey) {
                throw new Error('Private key not found. Please log in again.');
            }

            if (keyPairValid === false) {
                throw new Error('Your encryption keys are invalid. Please log in again.');
            }

            const password = passwords.find(p => p.id === id);
            if (!password) {
                throw new Error('Password not found');
            }

            if (!password.encrypted_password) {
                throw new Error('No encrypted password data found');
            }
            let decrypted;

            // Check if this is a shared password  or personal password
            if (password.owner !== 'Me' && password.sharedBy) {
                decrypted = await decryptSharedPassword(password.encrypted_password, currentPrivateKey);
            } else {
                console.log('Decrypting personal password using standard format...');
                // This is a personal password - use standard decryption
                decrypted = await decryptWithPrivateKey(password.encrypted_password, currentPrivateKey);
            }
            const finalDecryptedValue = typeof decrypted === 'string' ? decrypted : String(decrypted);

            setDecryptedPasswords(prev => ({
                ...prev,
                [id]: finalDecryptedValue
            }));
            setVisibleIndex(id);
        } catch (error) {
            console.error('Password decryption failed:', {
                passwordId: id,
                error: error.message,
                stack: error.stack
            });

            // Provide user-friendly error messages
            let userMessage = 'Failed to decrypt password';
            if (error.message.includes('Private key not found')) {
                userMessage = 'Authentication expired. Please log in again.';
                // Clear session and redirect to login
                sessionStorage.removeItem('user');
                sessionStorage.removeItem('privateKey');
                setUser(null);
                setPrivateKey(null);
                navigate('/login');
                return;
            } else if (error.message.includes('corrupted') || error.message.includes('wrong private key')) {
                userMessage = 'Unable to decrypt password. This may be due to key mismatch or data corruption.';
            } else if (error.message.includes('Invalid base64')) {
                userMessage = 'Password data appears to be corrupted.';
            }

            alert(userMessage);
        }
    };

    const renderPasswordTable = () => (
        <div className="homepage-main-body">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 className="homepage-section-title">YOUR PASSWORD TABLE</h2>
            </div>
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
                                    {visibleIndex === item.id ?
                                        (decryptedPasswords[item.id] || 'Decrypting...') :
                                        '••••••••'
                                    }
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
                                        <FaEye />
                                    </button>
                                    {item.owner === 'Me' && (
                                        <>
                                            <button className="btn-edit">
                                                <FaEdit />
                                            </button>
                                            <button className="btn-delete">
                                                <FaTrash />
                                            </button>
                                        </>
                                    )}
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

    const renderMainContent = () => {
        switch (activePage) {
            case 'createPassword':
                return <CreatePassword onPasswordAdded={fetchPasswords} />;
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

    // Update the loading condition
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
                {/* Top bar */}
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
                    <div className="homepage-icon-button"><FaBell size={20} /></div>
                </div>

                {/* Main content dynamic */}
                {renderMainContent()}
            </div>
        </div>
    );
}