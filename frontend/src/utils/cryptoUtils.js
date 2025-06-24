// ===============================================
// TRUE END-TO-END ENCRYPTION WITH FORWARD SECRECY
// Based on CS255 Project 2 Double Ratchet concepts
// ===============================================

// Session management for forward secrecy
const sessions = new Map();

// ===============================================
// UTILITY FUNCTIONS
// ===============================================

const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    return btoa(binary);
};

const base64ToArrayBuffer = (base64) => {
    try {
        // Clean the base64 string - remove any whitespace/newlines
        const cleanBase64 = base64.replace(/\s+/g, '');
        
        // Validate base64 format
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
            throw new Error('Invalid base64 format');
        }
        
        const binary = atob(cleanBase64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('Base64 decoding failed for input:', base64?.substring(0, 100));
        throw new Error(`Failed to decode base64: ${error.message}`);
    }
};

// ===============================================
// ECDH KEY GENERATION AND MANAGEMENT
// ===============================================

// Generate ECDH key pair for key exchange
export const generateECDHKeyPair = async () => {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

        return {
            publicKey: arrayBufferToBase64(publicKey),
            privateKey: arrayBufferToBase64(privateKey),
            keyPair: keyPair
        };
    } catch (error) {
        console.error('ECDH key generation failed:', error);
        throw new Error(`Failed to generate ECDH key pair: ${error.message}`);
    }
};

// ===============================================
// PRIVATE KEY ENCRYPTION/DECRYPTION FOR STORAGE
// ===============================================

export const encryptPrivateKey = async (privateKey, password) => {
    try {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        
        // Generate salt
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        
        // Derive key from password using PBKDF2
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passwordData,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        // Generate IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt private key
        const privateKeyData = encoder.encode(privateKey);
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            derivedKey,
            privateKeyData
        );
        
        // Combine salt, iv, and encrypted data
        const result = {
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(encryptedData)
        };
        
        return JSON.stringify(result);
    } catch (error) {
        console.error('Private key encryption failed:', error);
        throw new Error(`Failed to encrypt private key: ${error.message}`);
    }
};

export const decryptPrivateKey = async (encryptedPrivateKey, password) => {
    try {
        const encryptedData = JSON.parse(encryptedPrivateKey);
        const { salt, iv, ciphertext } = encryptedData;
        
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const passwordData = encoder.encode(password);
        
        // Derive the same key from password
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passwordData,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: base64ToArrayBuffer(salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: base64ToArrayBuffer(iv)
            },
            derivedKey,
            base64ToArrayBuffer(ciphertext)
        );
        
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('Private key decryption failed:', error);
        throw new Error(`Failed to decrypt private key: ${error.message}`);
    }
};

// ===============================================
// KEY IMPORT/EXPORT HELPERS
// ===============================================

export const importECDHPublicKey = async (publicKeyString) => {
    try {
        // Check if it's a PEM format key
        if (publicKeyString.includes('-----BEGIN PUBLIC KEY-----')) {
            console.log('Detected PEM format, converting...');
            // Extract base64 from PEM
            const base64Key = publicKeyString
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\n/g, '')
                .replace(/\r/g, '')
                .trim();
            
            console.log('Extracted base64 length:', base64Key.length);
            const keyData = base64ToArrayBuffer(base64Key);
            
            return await window.crypto.subtle.importKey(
                "spki",
                keyData,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                []
            );
        } else {
            const keyData = base64ToArrayBuffer(publicKeyString);
            
            return await window.crypto.subtle.importKey(
                "spki",
                keyData,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                []
            );
        }
    } catch (error) {
        console.error('ECDH public key import failed:', error);
        console.error('Failed key data:', {
            length: publicKeyString?.length,
            preview: publicKeyString?.substring(0, 100),
            isPEM: publicKeyString?.includes('-----BEGIN')
        });
        throw new Error(`Failed to import ECDH public key: ${error.message}`);
    }
};

export const importECDHPrivateKey = async (privateKeyString) => {
    try {
        // Check if it's a PEM format key
        if (privateKeyString.includes('-----BEGIN PRIVATE KEY-----')) {
            console.log('Detected PEM format private key, converting...');
            // Extract base64 from PEM
            const base64Key = privateKeyString
                .replace('-----BEGIN PRIVATE KEY-----', '')
                .replace('-----END PRIVATE KEY-----', '')
                .replace(/\n/g, '')
                .replace(/\r/g, '')
                .trim();
            
            const keyData = base64ToArrayBuffer(base64Key);
            
            return await window.crypto.subtle.importKey(
                "pkcs8",
                keyData,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );
        } else {
            // Assume it's already base64
            const keyData = base64ToArrayBuffer(privateKeyString);
            
            return await window.crypto.subtle.importKey(
                "pkcs8",
                keyData,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );
        }
    } catch (error) {
        console.error('ECDH private key import failed:', error);
        throw new Error(`Failed to import ECDH private key: ${error.message}`);
    }
};

// ===============================================
// PASSWORD ENCRYPTION WITH ECDH
// ===============================================

export const encryptWithPublicKey = async (data, publicKeyString) => {
    try {
        // Generate ephemeral key pair for this encryption
        const ephemeralKeyPair = await generateECDHKeyPair();
        
        // Import recipient's public key
        const recipientPublicKey = await importECDHPublicKey(publicKeyString);
        const ephemeralPrivateKey = await importECDHPrivateKey(ephemeralKeyPair.privateKey);
        
        // Derive shared secret
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: recipientPublicKey
            },
            ephemeralPrivateKey,
            256
        );
        
        // Derive encryption key from shared secret
        const encryptionKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );
        
        // Generate IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt data
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            encryptionKey,
            dataBuffer
        );
        
        return JSON.stringify({
            ephemeralPublicKey: ephemeralKeyPair.publicKey,
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(encryptedData)
        });
    } catch (error) {
        console.error('ECDH encryption failed:', error);
        throw new Error(`Failed to encrypt with public key: ${error.message}`);
    }
};

export const decryptWithPrivateKey = async (encryptedData, privateKeyString) => {
    try {
        const { ephemeralPublicKey, iv, ciphertext } = JSON.parse(encryptedData);
        
        // Import keys
        const ephemeralPubKey = await importECDHPublicKey(ephemeralPublicKey);
        const recipientPrivateKey = await importECDHPrivateKey(privateKeyString);
        
        // Derive shared secret
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: ephemeralPubKey
            },
            recipientPrivateKey,
            256
        );
        
        // Derive decryption key from shared secret
        const decryptionKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        
        // Decrypt data
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: base64ToArrayBuffer(iv)
            },
            decryptionKey,
            base64ToArrayBuffer(ciphertext)
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('ECDH decryption failed:', error);
        throw new Error(`Failed to decrypt with private key: ${error.message}`);
    }
};

// ===============================================
// KEY TESTING AND VALIDATION
// ===============================================

export const testKeyPair = async (publicKey, privateKey) => {
    try {
        // Test message
        const testMessage = "test-key-pair-validation";
        
        // Import keys for testing
        const pubKey = await importECDHPublicKey(publicKey);
        const privKey = await importECDHPrivateKey(privateKey);
        
        // Try to derive a shared secret (basic validation)
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: pubKey
            },
            privKey,
            256
        );
        
        return sharedSecret.byteLength === 32; // Should be 256 bits = 32 bytes
    } catch (error) {
        console.error('Key pair validation failed:', error);
        return false;
    }
};

// ===============================================
// KEY EXCHANGE & SESSION ESTABLISHMENT
// ===============================================

export const establishSession = async (myPrivateKey, theirPublicKey, sessionId) => {
    try {
        // Import keys
        const privateKey = await importECDHPrivateKey(myPrivateKey);
        const publicKey = await importECDHPublicKey(theirPublicKey);

        // Derive shared secret using ECDH
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: publicKey
            },
            privateKey,
            256
        );

        // Initialize session with forward secrecy
        const session = {
            sharedSecret: new Uint8Array(sharedSecret),
            sendingChainKey: null,
            receivingChainKey: null,
            rootKey: null,
            messageNumber: 0,
            previousMessageNumber: 0
        };

        // Derive initial root key from shared secret
        session.rootKey = await deriveRootKey(session.sharedSecret, sessionId);
        
        // Derive initial chain keys
        const { chainKey: sendingChain, nextRootKey } = await deriveChainKey(session.rootKey, "sending");
        session.sendingChainKey = sendingChain;
        session.receivingChainKey = await deriveChainKey(nextRootKey, "receiving").then(r => r.chainKey);

        // Store session
        sessions.set(sessionId, session);

        console.log(`Session established: ${sessionId}`);
        return sessionId;
    } catch (error) {
        console.error('Session establishment failed:', error);
        throw new Error(`Failed to establish session: ${error.message}`);
    }
};

// ===============================================
// FORWARD SECRECY KEY RATCHETING
// ===============================================

const deriveRootKey = async (sharedSecret, info) => {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret,
        { name: "HKDF" },
        false,
        ["deriveKey"]
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(32), // Should be random in production
            info: encoder.encode(info)
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
};

const deriveChainKey = async (rootKey, direction) => {
    const encoder = new TextEncoder();
    const directionBytes = encoder.encode(direction);
    
    // Sign to create chain key
    const chainKeyBytes = await window.crypto.subtle.sign(
        "HMAC",
        rootKey,
        directionBytes
    );

    // Import as HMAC key for further derivation
    const chainKey = await window.crypto.subtle.importKey(
        "raw",
        chainKeyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    // Derive next root key for ratcheting
    const nextRootKeyBytes = await window.crypto.subtle.sign(
        "HMAC",
        rootKey,
        encoder.encode(`${direction}-next`)
    );

    const nextRootKey = await window.crypto.subtle.importKey(
        "raw",
        nextRootKeyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    return { chainKey, nextRootKey };
};

const deriveMessageKey = async (chainKey, messageNumber) => {
    const encoder = new TextEncoder();
    const messageInfo = encoder.encode(`message-${messageNumber}`);
    
    const messageKeyBytes = await window.crypto.subtle.sign(
        "HMAC",
        chainKey,
        messageInfo
    );

    // Create AES key for actual encryption
    return await window.crypto.subtle.importKey(
        "raw",
        messageKeyBytes.slice(0, 32), // Use first 32 bytes for AES-256
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

// ===============================================
// END-TO-END ENCRYPTION/DECRYPTION
// ===============================================

export const encryptMessage = async (message, sessionId, recipientId) => {
    try {
        const session = sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session not found: ${sessionId}`);
        }

        // Derive message key with forward secrecy
        const messageKey = await deriveMessageKey(session.sendingChainKey, session.messageNumber);
        
        // Generate random IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt message
        const encoder = new TextEncoder();
        const messageData = encoder.encode(JSON.stringify({ 
            content: message,
            timestamp: Date.now(),
            sender: sessionId.split('-')[0] // Assuming sessionId format: "sender-recipient"
        }));

        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            messageKey,
            messageData
        );

        // Create message header with metadata
        const header = {
            messageNumber: session.messageNumber,
            iv: arrayBufferToBase64(iv),
            sessionId: sessionId,
            timestamp: Date.now()
        };

        // Advance the ratchet (forward secrecy)
        session.messageNumber++;
        const { chainKey: newChainKey } = await deriveChainKey(session.sendingChainKey, `msg-${session.messageNumber}`);
        session.sendingChainKey = newChainKey;

        return {
            header: header,
            ciphertext: arrayBufferToBase64(encryptedData)
        };

    } catch (error) {
        console.error('Message encryption failed:', error);
        throw new Error(`Failed to encrypt message: ${error.message}`);
    }
};

export const decryptMessage = async (encryptedMessage, sessionId) => {
    try {
        const { header, ciphertext } = encryptedMessage;
        const session = sessions.get(sessionId);
        
        if (!session) {
            throw new Error(`Session not found: ${sessionId}`);
        }

        // Derive the same message key used for encryption
        const messageKey = await deriveMessageKey(session.receivingChainKey, header.messageNumber);
        
        // Decrypt message
        const encryptedData = base64ToArrayBuffer(ciphertext);
        const iv = base64ToArrayBuffer(header.iv);

        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            messageKey,
            encryptedData
        );

        const decoder = new TextDecoder();
        const messageData = JSON.parse(decoder.decode(decryptedData));

        // Advance receiving chain ratchet
        const { chainKey: newChainKey } = await deriveChainKey(session.receivingChainKey, `msg-${header.messageNumber + 1}`);
        session.receivingChainKey = newChainKey;

        return messageData.content;

    } catch (error) {
        console.error('Message decryption failed:', error);
        throw new Error(`Failed to decrypt message: ${error.message}`);
    }
};

// ===============================================
// SIMPLIFIED PASSWORD SHARING (EVEN SIMPLER)
// ===============================================

export const encryptPasswordForSharing = async (password, recipientPublicKey) => {
    try {
        // This is the simplest approach - just use your existing encryptWithPublicKey
        return await encryptWithPublicKey(password, recipientPublicKey);
    } catch (error) {
        console.error('Simple password encryption failed:', error);
        throw new Error(`Failed to encrypt password: ${error.message}`);
    }
};

export const decryptSharedPassword = async (encryptedData, recipientPrivateKey) => {
    try {
        // Parse the E2E encrypted data
        const { ephemeralPublicKey, iv, ciphertext } = JSON.parse(encryptedData);

        // Import keys
        const ephemeralPubKey = await importECDHPublicKey(ephemeralPublicKey);
        const recipientPrivKey = await importECDHPrivateKey(recipientPrivateKey);
        
        // Derive shared secret using ECDH
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: ephemeralPubKey
            },
            recipientPrivKey,
            256
        );
        
        // Create decryption key from shared secret
        const decryptionKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        
        // Decrypt data
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: base64ToArrayBuffer(iv)
            },
            decryptionKey,
            base64ToArrayBuffer(ciphertext)
        );
        
        const decoder = new TextDecoder();
        const decryptedText = decoder.decode(decryptedData);
        
        // The encrypted data might be JSON with additional metadata
        try {
            const parsed = JSON.parse(decryptedText);
            console.log('Decrypted data is JSON:', Object.keys(parsed));
            return parsed.password || decryptedText; // Return just the password if it's wrapped
        } catch (e) {
            return decryptedText; 
        }
        
    } catch (error) {
        console.error('=== Shared Password Decryption Error ===');
        console.error('Error type:', error.constructor.name);
        console.error('Error message:', error.message);
        console.error('Stack trace:', error.stack);
        throw new Error(`Failed to decrypt shared password: ${error.message}`);
    }
};