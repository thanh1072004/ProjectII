const sessions = new Map();

// Chuyển đổi ArrayBuffer thành base64
const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    return btoa(binary);
};

// Chuyển đổi base64 thành ArrayBuffer
const base64ToArrayBuffer = (base64) => {
    try {
        if (!base64 || typeof base64 !== 'string') {
            throw new Error('Input must be a non-empty string');
        }
        const cleanBase64 = base64.replace(/\s+/g, '');
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

// Tạo khóa AES tạm thời
export const generateTempAESKey = async () => {
    try {
        const key = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
        const exportedKey = await window.crypto.subtle.exportKey('raw', key);
        return arrayBufferToBase64(exportedKey);
    } catch (error) {
        console.error('Failed to generate temp AES key:', error);
        throw new Error(`Failed to generate temp AES key: ${error.message}`);
    }
};

// Mã hóa bằng AES-GCM
export const encryptWithAES = async (data, key) => {
    try {
        if (!data || !key) {
            throw new Error('Missing data or key');
        }
        const encoder = new TextEncoder();
        const keyBuffer = base64ToArrayBuffer(key);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            encoder.encode(data)
        );

        const encryptedArray = new Uint8Array(encryptedData);
        const authTag = encryptedArray.slice(-16); // AES-GCM auth tag là 16 bytes
        const ciphertext = encryptedArray.slice(0, -16);

        return JSON.stringify({
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
            authTag: arrayBufferToBase64(authTag)
        });
    } catch (error) {
        console.error('AES encryption failed:', error);
        throw new Error(`Failed to encrypt with AES: ${error.message}`);
    }
};

// Tạo cặp khóa ECDH với P-256
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

// Mã hóa private key với mật khẩu
export const encryptPrivateKey = async (privateKey, password) => {
    try {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        
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
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const privateKeyData = encoder.encode(privateKey);
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            derivedKey,
            privateKeyData
        );
        
        const encryptedArray = new Uint8Array(encryptedData);
        const authTag = encryptedArray.slice(-16); // AES-GCM auth tag là 16 bytes
        const ciphertext = encryptedArray.slice(0, -16);
        
        return JSON.stringify({
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
            authTag: arrayBufferToBase64(authTag)
        });
    } catch (error) {
        console.error('Private key encryption failed:', error);
        throw new Error(`Failed to encrypt private key: ${error.message}`);
    }
};

// Giải mã private key
export const decryptPrivateKey = async (encryptedPrivateKey, password) => {
    try {
        let data;
        try {
            data = typeof encryptedPrivateKey === 'string' ? JSON.parse(encryptedPrivateKey) : encryptedPrivateKey;
        } catch (parseError) {
            console.error('Lỗi phân tích encryptedPrivateKey:', parseError.message);
            throw new Error('Dữ liệu khóa riêng không hợp lệ: Không phải JSON hợp lệ');
        }

        const { iv, ciphertext, authTag, salt } = data;
        if (!iv || !ciphertext || !authTag || !salt) {
            console.error('Dữ liệu mã hóa khóa riêng không hợp lệ:', data);
            throw new Error('Thiếu iv, ciphertext, authTag hoặc salt trong dữ liệu mã hóa');
        }

        console.log('Dữ liệu mã hóa khóa riêng:', { iv, ciphertext, authTag, salt });

        const passwordBuffer = new TextEncoder().encode(password);
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const saltBuffer = base64ToArrayBuffer(salt);
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const ivBuffer = base64ToArrayBuffer(iv);
        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const authTagBuffer = base64ToArrayBuffer(authTag);

        const combinedBuffer = new Uint8Array(ciphertextBuffer.byteLength + authTagBuffer.byteLength);
        combinedBuffer.set(new Uint8Array(ciphertextBuffer), 0);
        combinedBuffer.set(new Uint8Array(authTagBuffer), ciphertextBuffer.byteLength);

        console.log('Kích thước buffer kết hợp:', combinedBuffer.length);

        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer
            },
            derivedKey,
            combinedBuffer
        );

        const decoder = new TextDecoder();
        const privateKey = decoder.decode(decryptedData);
        console.log('Khóa riêng đã giải mã:', privateKey.substring(0, 50) + '...');

        return privateKey;
    } catch (error) {
        console.error('Lỗi giải mã khóa riêng:', {
            message: error.message,
            stack: error.stack,
            encryptedPrivateKey: JSON.stringify(encryptedPrivateKey, null, 2)
        });
        throw new Error(`Không thể giải mã khóa riêng: ${error.message}`);
    }
};

// Nhập public key
export const importECDHPublicKey = async (publicKeyString) => {
    try {
        if (publicKeyString.includes('-----BEGIN PUBLIC KEY-----')) {
            console.log('Detected PEM format, converting...');
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

// Nhập private key
export const importECDHPrivateKey = async (privateKeyString) => {
    try {
        if (privateKeyString.includes('-----BEGIN PRIVATE KEY-----')) {
            console.log('Detected PEM format private key, converting...');
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

// Mã hóa với public key
export const encryptWithPublicKey = async (data, publicKeyString) => {
    try {
        console.log('Encrypting with publicKey:', publicKeyString.substring(0, 20) + '...');
        const ephemeralKeyPair = await generateECDHKeyPair();
        const recipientPublicKey = await importECDHPublicKey(publicKeyString);
        const ephemeralPrivateKey = await importECDHPrivateKey(ephemeralKeyPair.privateKey);
        
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: recipientPublicKey
            },
            ephemeralPrivateKey,
            256
        );
        
        const encryptionKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
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
        
        const encryptedArray = new Uint8Array(encryptedData);
        const authTag = encryptedArray.slice(-16); // AES-GCM auth tag là 16 bytes
        const ciphertext = encryptedArray.slice(0, -16);

        const result = {
            ephemeralPublicKey: ephemeralKeyPair.publicKey,
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
            authTag: arrayBufferToBase64(authTag)
        };

        console.log('Encryption result:', {
            ephemeralPublicKey: result.ephemeralPublicKey.substring(0, 20) + '...',
            iv: result.iv,
            ciphertext: result.ciphertext.substring(0, 20) + '...',
            authTag: result.authTag
        });

        return result;
    } catch (error) {
        console.error('ECDH encryption failed:', {
            message: error.message,
            stack: error.stack,
            publicKeyPreview: publicKeyString.substring(0, 20) + '...'
        });
        throw new Error(`Failed to encrypt with public key: ${error.message}`);
    }
};

// Giải mã với private key
export const decryptWithPrivateKey = async (encryptedData, privateKeyString) => {
    try {
        const data = typeof encryptedData === 'string' ? JSON.parse(encryptedData) : encryptedData;
        const { ephemeralPublicKey, iv, ciphertext, authTag } = data;

        if (!ephemeralPublicKey || !iv || !ciphertext || !authTag) {
            throw new Error('Invalid encrypted data format: Missing ephemeralPublicKey, iv, ciphertext, or authTag');
        }

        const ephemeralPubKey = await importECDHPublicKey(ephemeralPublicKey);
        const recipientPrivateKey = await importECDHPrivateKey(privateKeyString);

        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: ephemeralPubKey
            },
            recipientPrivateKey,
            256
        );

        const decryptionKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const authTagBuffer = base64ToArrayBuffer(authTag);
        const combinedBuffer = new Uint8Array(ciphertextBuffer.byteLength + authTagBuffer.byteLength);
        combinedBuffer.set(new Uint8Array(ciphertextBuffer), 0);
        combinedBuffer.set(new Uint8Array(authTagBuffer), ciphertextBuffer.byteLength);

        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: base64ToArrayBuffer(iv)
            },
            decryptionKey,
            combinedBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('ECDH decryption failed:', {
            message: error.message,
            stack: error.stack,
            encryptedData: JSON.stringify(encryptedData, null, 2)
        });
        throw new Error(`Failed to decrypt with private key: ${error.message}`);
    }
};

// Kiểm tra cặp khóa
export const testKeyPair = async (publicKey, privateKey) => {
    try {
        const testMessage = "test-key-pair-validation";
        const pubKey = await importECDHPublicKey(publicKey);
        const privKey = await importECDHPrivateKey(privateKey);
        
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: pubKey
            },
            privKey,
            256
        );
        
        return sharedSecret.byteLength === 32;
    } catch (error) {
        console.error('Key pair validation failed:', error);
        return false;
    }
};

// Các hàm session và message giữ nguyên
export const establishSession = async (myPrivateKey, theirPublicKey, sessionId) => {
    try {
        const privateKey = await importECDHPrivateKey(myPrivateKey);
        const publicKey = await importECDHPublicKey(theirPublicKey);

        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: publicKey
            },
            privateKey,
            256
        );

        const session = {
            sharedSecret: new Uint8Array(sharedSecret),
            sendingChainKey: null,
            receivingChainKey: null,
            rootKey: null,
            messageNumber: 0,
            previousMessageNumber: 0
        };

        session.rootKey = await deriveRootKey(session.sharedSecret, sessionId);
        
        const { chainKey: sendingChain, nextRootKey } = await deriveChainKey(session.rootKey, "sending");
        session.sendingChainKey = sendingChain;
        session.receivingChainKey = await deriveChainKey(nextRootKey, "receiving").then(r => r.chainKey);

        sessions.set(sessionId, session);

        console.log(`Session established: ${sessionId}`);
        return sessionId;
    } catch (error) {
        console.error('Session establishment failed:', error);
        throw new Error(`Failed to establish session: ${error.message}`);
    }
};

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
            salt: new Uint8Array(32),
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
    
    const chainKeyBytes = await window.crypto.subtle.sign(
        "HMAC",
        rootKey,
        directionBytes
    );

    const chainKey = await window.crypto.subtle.importKey(
        "raw",
        chainKeyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

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

    return await window.crypto.subtle.importKey(
        "raw",
        messageKeyBytes.slice(0, 32),
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

export const encryptMessage = async (message, sessionId, recipientId) => {
    try {
        const session = sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session not found: ${sessionId}`);
        }

        const messageKey = await deriveMessageKey(session.sendingChainKey, session.messageNumber);
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encoder = new TextEncoder();
        const messageData = encoder.encode(JSON.stringify({ 
            content: message,
            timestamp: Date.now(),
            sender: sessionId.split('-')[0]
        }));

        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            messageKey,
            messageData
        );

        const header = {
            messageNumber: session.messageNumber,
            iv: arrayBufferToBase64(iv),
            sessionId: sessionId,
            timestamp: Date.now()
        };

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

        const messageKey = await deriveMessageKey(session.receivingChainKey, header.messageNumber);
        
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

        const { chainKey: newChainKey } = await deriveChainKey(session.receivingChainKey, `msg-${header.messageNumber + 1}`);
        session.receivingChainKey = newChainKey;

        return messageData.content;
    } catch (error) {
        console.error('Message decryption failed:', error);
        throw new Error(`Failed to decrypt message: ${error.message}`);
    }
};

export const encryptPasswordForSharing = async (password, recipientPublicKey) => {
    try {
        const result = await encryptWithPublicKey(password, recipientPublicKey);
        console.log('Password sharing encryption result:', {
            ephemeralPublicKey: result.ephemeralPublicKey.substring(0, 20) + '...',
            iv: result.iv,
            ciphertext: result.ciphertext.substring(0, 20) + '...',
            authTag: result.authTag
        });
        return result;
    } catch (error) {
        console.error('Simple password encryption failed:', error);
        throw new Error(`Failed to encrypt password: ${error.message}`);
    }
};

export const decryptSharedPassword = async (encryptedData, recipientPrivateKey) => {
    try {
        return await decryptWithPrivateKey(encryptedData, recipientPrivateKey);
    } catch (error) {
        console.error('=== Shared Password Decryption Error ===', {
            message: error.message,
            stack: error.stack,
            encryptedData: JSON.stringify(encryptedData, null, 2)
        });
        throw new Error(`Failed to decrypt shared password: ${error.message}`);
    }
};