const crypto = require('crypto');
const util = require('util');
const generateKeyPair = util.promisify(crypto.generateKeyPair);

const arrayBufferToBase64 = (buffer) => {
    return buffer.toString('base64');
};

const base64ToBuffer = (base64) => {
    try {
        if (!base64 || typeof base64 !== 'string') {
            throw new Error('Input must be a non-empty string');
        }
        const cleanBase64 = base64.replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
            throw new Error('Invalid base64 format');
        }
        return Buffer.from(cleanBase64, 'base64');
    } catch (error) {
        console.error('Base64 decoding failed:', base64?.substring(0, 100));
        throw new Error(`Failed to decode base64: ${error.message}`);
    }
};

// generate key pair ECDH with P-256
const generateECDHKeyPair = async () => {
    try {
        const { publicKey, privateKey } = await generateKeyPair('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'der' },
            privateKeyEncoding: { type: 'pkcs8', format: 'der' }
        });
        return {
            publicKey: arrayBufferToBase64(publicKey),
            privateKey: arrayBufferToBase64(privateKey)
        };
    } catch (error) {
        console.error('ECDH key generation failed:', error);
        throw new Error(`Failed to generate ECDH key pair: ${error.message}`);
    }
};

const encryptPrivateKey = (privateKey, password) => {
    try {
        console.log('Encrypting private key with password');
        const salt = crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(privateKey, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();

        const result = {
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            ciphertext: encrypted,
            authTag: arrayBufferToBase64(authTag)
        };

        console.log('Private key encryption result:', {
            salt: result.salt,
            iv: result.iv,
            ciphertext: result.ciphertext.substring(0, 20) + '...',
            authTag: result.authTag
        });

        return JSON.stringify(result);
    } catch (error) {
        console.error('Private key encryption failed:', {
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to encrypt private key: ${error.message}`);
    }
};

const importPublicKey = async (publicKeyString) => {
    try {
        let keyBuffer;
        if (publicKeyString.includes('-----BEGIN PUBLIC KEY-----')) {
            console.log('Detected PEM format, converting to DER...');
            const base64Key = publicKeyString
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\n/g, '')
                .replace(/\r/g, '')
                .trim();
            keyBuffer = base64ToBuffer(base64Key);
        } else {
            console.log('Assuming Base64 DER format for publicKey');
            keyBuffer = base64ToBuffer(publicKeyString);
        }

        console.log('Importing public key:', {
            length: publicKeyString.length,
            preview: publicKeyString.substring(0, 20) + '...',
            isPEM: publicKeyString.includes('-----BEGIN')
        });

        const publicKey = crypto.createPublicKey({
            key: keyBuffer,
            format: 'der',
            type: 'spki'
        });

        const keyDetails = publicKey.asymmetricKeyDetails;
        if (keyDetails?.namedCurve !== 'prime256v1') {
            throw new Error(`Public key is not valid for P-256 curve, found: ${keyDetails?.namedCurve || 'unknown'}`);
        }

        return publicKey;
    } catch (error) {
        console.error('ECDH public key import failed:', {
            message: error.message,
            stack: error.stack,
            publicKeyPreview: publicKeyString.substring(0, 20) + '...'
        });
        throw new Error(`Failed to import ECDH public key: ${error.message}`);
    }
};

const encryptPasswordForSharing = async (password, publicKeyString) => {
    try {
        console.log('Encrypting password with publicKey:', publicKeyString.substring(0, 20) + '...');
        const publicKey = await importPublicKey(publicKeyString);

        const ephemeralKeyPair = await generateECDHKeyPair();
        const ephemeralPublicKey = crypto.createPublicKey({
            key: base64ToBuffer(ephemeralKeyPair.publicKey),
            format: 'der',
            type: 'spki'
        });

        const sharedSecret = crypto.diffieHellman({
            publicKey: publicKey,
            privateKey: crypto.createPrivateKey({
                key: base64ToBuffer(ephemeralKeyPair.privateKey),
                format: 'der',
                type: 'pkcs8'
            })
        });

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecret, iv);
        let encrypted = cipher.update(password, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();

        const result = {
            ephemeralPublicKey: ephemeralKeyPair.publicKey,
            iv: arrayBufferToBase64(iv),
            ciphertext: encrypted,
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
        console.error('Password encryption failed:', {
            message: error.message,
            stack: error.stack,
            publicKeyPreview: publicKeyString.substring(0, 20) + '...'
        });
        throw new Error(`Failed to encrypt password: ${error.message}`);
    }
};

const decryptSharedPassword = async (encryptedData, privateKeyString) => {
    try {
        const { ephemeralPublicKey, iv, ciphertext, authTag } = encryptedData;

        console.log('Decrypting with ephemeralPublicKey:', ephemeralPublicKey.substring(0, 20) + '...');

        const privateKey = crypto.createPrivateKey({
            key: base64ToBuffer(privateKeyString),
            format: 'der',
            type: 'pkcs8'
        });

        const ephemeralPublicKeyObj = crypto.createPublicKey({
            key: base64ToBuffer(ephemeralPublicKey),
            format: 'der',
            type: 'spki'
        });

        const sharedSecret = crypto.diffieHellman({
            publicKey: ephemeralPublicKeyObj,
            privateKey: privateKey
        });

        const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret, base64ToBuffer(iv));
        decipher.setAuthTag(base64ToBuffer(authTag));
        let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        console.log('Decryption successful');
        return decrypted;
    } catch (error) {
        console.error('Shared password decryption failed:', {
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to decrypt shared password: ${error.message}`);
    }
};

const generateTempAESKey = async () => {
    try {
        const key = crypto.randomBytes(32);
        return arrayBufferToBase64(key);
    } catch (error) {
        console.error('Failed to generate temp AES key:', error);
        throw new Error(`Failed to generate temp AES key: ${error.message}`);
    }
};

const encryptWithAES = async (data, key) => {
    try {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', base64ToBuffer(key), iv);
        let encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();

        return JSON.stringify({
            iv: arrayBufferToBase64(iv),
            ciphertext: encrypted,
            authTag: arrayBufferToBase64(authTag)
        });
    } catch (error) {
        console.error('AES encryption failed:', error);
        throw new Error(`Failed to encrypt with AES: ${error.message}`);
    }
};

const decryptWithAES = async (encryptedData, key) => {
    try {
        const { iv, ciphertext, authTag } = JSON.parse(encryptedData);
        const decipher = crypto.createDecipheriv('aes-256-gcm', base64ToBuffer(key), base64ToBuffer(iv));
        decipher.setAuthTag(base64ToBuffer(authTag));
        let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('AES decryption failed:', error);
        throw new Error(`Failed to decrypt with AES: ${error.message}`);
    }
};

module.exports = {
    generateECDHKeyPair,
    importPublicKey,
    encryptPrivateKey,
    encryptPasswordForSharing,
    decryptSharedPassword,
    generateTempAESKey,
    encryptWithAES,
    decryptWithAES
};