import { useState, useEffect } from 'react';
import axios from 'axios';
import './SharePassword.css';
import { encryptPasswordForSharing, decryptWithPrivateKey } from '../../../utils/cryptoUtils';

export default function SharePassword() {
    const [recipientEmail, setRecipientEmail] = useState('');
    const [isSharing, setIsSharing] = useState(false);
    const [error, setError] = useState(null);
    const [userPasswords, setUserPasswords] = useState([]);
    const [selectedPasswordId, setSelectedPasswordId] = useState('');
    const [decryptedPasswords, setDecryptedPasswords] = useState({});
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetchUserPasswords();
    }, []); 

    axios.defaults.withCredentials = true;

    const fetchUserPasswords = async () => {
        try {
            setLoading(true);
            const response = await axios.get(`${import.meta.env.VITE_API_URL}/employee/passwords`);
            if (response.data.passwords) {
                setUserPasswords(response.data.passwords);
                if (response.data.passwords.length > 0) {
                    setSelectedPasswordId(response.data.passwords[0].id);
                }
            }
        } catch (error) {
            console.error('Failed to fetch passwords:', error);
            setError('Failed to fetch passwords');
        } finally {
            setLoading(false);
        }
    };

    const validateInput = () => {
        if (!recipientEmail) {
            setError('Recipient email is required');
            return false;
        }
        if (!selectedPasswordId) {
            setError('Please select a password to share');
            return false;
        }
        return true;
    };

    // Decrypt a specific password
    const decryptPassword = async (passwordEntry) => {
        try {
            const privateKey = sessionStorage.getItem('privateKey');
            if (!privateKey) {
                throw new Error('Private key not found. Please log in again.');
            }
            const decryptedPassword = await decryptWithPrivateKey(
                passwordEntry.encrypted_password, 
                privateKey
            );
            
            // Store the decrypted password
            setDecryptedPasswords(prev => ({
                ...prev,
                [passwordEntry._id]: decryptedPassword
            }));
            
            return decryptedPassword;
        } catch (error) {
            console.error('Failed to decrypt password:', error);
            throw new Error(`Failed to decrypt password: ${error.message}`);
        }
    };

    const handleShare = async (e) => {
        e.preventDefault();
        setError(null);

        if (!validateInput()) return;
        setIsSharing(true);

        try {
            // Get recipient's public key
            const keyResponse = await axios.get(
                `${import.meta.env.VITE_API_URL}/employee/users/${recipientEmail}/public-key`
            );
            
            console.log('API Response:', keyResponse.data);
            const recipientPublicKey = keyResponse.data.publicKey || keyResponse.data.ecdhPublicKey;
            
            if (!recipientPublicKey) {
                throw new Error('Recipient public key not found');
            }

            // Get the selected password
            const selectedPassword = userPasswords.find(p => p.id === selectedPasswordId);
            if (!selectedPassword) {
                throw new Error('Selected password not found');
            }
            
            // Get the plain password (you'll need to decrypt it first if it's encrypted)
            const plainPassword = await decryptPassword(selectedPassword);
            if (!plainPassword) {
                throw new Error('Password data not available. Please decrypt the password first.');
            }
        
            // Encrypt using simple E2E encryption
            const encryptedPasswordData = await encryptPasswordForSharing(
                plainPassword,
                recipientPublicKey
            );
            

            // Send to server
            const response = await axios.post(
                `${import.meta.env.VITE_API_URL}/employee/share-password`,
                {
                    recipientEmail,
                    encryptedPasswordData,
                    passwordMetadata: {
                        name: selectedPassword.name,
                        website: selectedPassword.website,
                        username: selectedPassword.username,
                        passwordId: selectedPasswordId
                    }
                },
                { withCredentials: true }
            );

            console.log('Server response:', response.data);
            alert('Password shared with end-to-end encryption!');
            setRecipientEmail('');

        } catch (error) {
            console.error('=== Share Error ===');
            console.error('Error type:', error.constructor.name);
            console.error('Error message:', error.message);
            console.error('Full error:', error);
            
            let errorMessage = 'Failed to share password';
            
            if (error.response?.data?.error) {
                errorMessage = error.response.data.error;
            } else if (error.message.includes('public key')) {
                errorMessage = 'Recipient not found or invalid public key';
            } else if (error.message) {
                errorMessage = error.message;
            }
            
            setError(errorMessage);
        } finally {
            setIsSharing(false);
        }
    };

    return (
        <div className="share-password-container">
            <h3>Share Password</h3>
            {error && <div className="error-message">{error}</div>}

            <form onSubmit={handleShare} className="share-password-form">
                <div className="form-group">
                    <label htmlFor="recipientEmail">Recipient Email:</label>
                    <input
                        id="recipientEmail"
                        type="email"
                        value={recipientEmail}
                        onChange={(e) => setRecipientEmail(e.target.value)}
                        placeholder="Enter recipient's email"
                        disabled={isSharing}
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="passwordSelect">Select Password to Share:</label>
                    <select
                        id="passwordSelect"
                        value={selectedPasswordId}
                        onChange={(e) => setSelectedPasswordId(e.target.value)}
                        disabled={isSharing}
                        className="password-select"
                    >
                        <option value="">Select a password</option>
                        {userPasswords.map(pwd => (
                            <option key={pwd.id} value={pwd.id}>
                                {pwd.name} - {pwd.website}
                            </option>
                        ))}
                    </select>
                </div>

                {selectedPasswordId && (
                    <div className="form-group">
                        <label>Password Details:</label>
                        <div className="password-preview">
                            <strong>Name:</strong> {userPasswords.find(p => p.id === selectedPasswordId)?.name}<br/>
                            <strong>Website:</strong> {userPasswords.find(p => p.id === selectedPasswordId)?.website}<br/>
                            <strong>Username:</strong> {userPasswords.find(p => p.id === selectedPasswordId)?.username}
                        </div>
                    </div>
                )}

                <button
                    type="submit"
                    disabled={isSharing || !selectedPasswordId}
                    className={`share-button ${isSharing ? 'loading' : ''}`}
                >
                    {isSharing ? ' Encrypting...' : 'Share Securely'}
                </button>
            </form>


        </div>
    );
}