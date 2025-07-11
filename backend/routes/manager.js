const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Company = require('../models/company');
const { requireManager } = require('./helper');
const { encryptPasswordForSharing, decryptWithAES } = require('../utils/cryptoUtils');

router.get('/passwords', async (req, res) => {
    try {
        console.log('Fetching passwords for user:', req.user.email, 'Role:', req.user.role);
        const user = await User.findById(req.user.id);
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }
        console.log('Found user:', user.email, 'Personal passwords:', user.personalPasswordTable.length, 'Shared passwords:', user.sharedPasswordTable.length);
        res.json({
            personalPasswords: user.personalPasswordTable,
            sharedPasswords: user.sharedPasswordTable
        });
    } catch (err) {
        console.error('Error fetching passwords:', err);
        res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
});

router.post('/add-password', requireManager, async (req, res) => {
    const { name, website, username, encrypted_password, tempAESKey, encryptedPlainPassword } = req.body;

    try {
        console.log('POST /api/manager/add-password called by:', req.user.email);
        console.log('Received request body:', {
            name,
            website,
            username,
            encryptedPassword: typeof encrypted_password === 'string' ? encrypted_password.substring(0, 50) + '...' : encrypted_password,
            tempAESKey: tempAESKey?.substring(0, 20) + '...',
            encryptedPlainPassword: typeof encryptedPlainPassword === 'string' ? encryptedPlainPassword.substring(0, 50) + '...' : encryptedPlainPassword
        });

        if (!name || !username || !encrypted_password || !tempAESKey || !encryptedPlainPassword) {
            console.error('Missing required fields:', { name, username, hasEncryptedPassword: !!encrypted_password, hasTempAESKey: !!tempAESKey, hasEncryptedPlainPassword: !!encryptedPlainPassword });
            return res.status(400).json({ error: 'Missing required fields: name, username, encrypted_password, tempAESKey, encryptedPlainPassword' });
        }

        let parsedEncryptedPassword;
        try {
            parsedEncryptedPassword = typeof encrypted_password === 'string' ? JSON.parse(encrypted_password) : encrypted_password;
            if (!parsedEncryptedPassword.ephemeralPublicKey || !parsedEncryptedPassword.iv || !parsedEncryptedPassword.ciphertext || !parsedEncryptedPassword.authTag) {
                throw new Error('Invalid encrypted_password format: Missing ephemeralPublicKey, iv, ciphertext, or authTag');
            }
        } catch (error) {
            console.error('Invalid encrypted_password format:', error.message);
            return res.status(400).json({ error: 'Invalid encrypted_password format, must be valid JSON with ephemeralPublicKey, iv, ciphertext, and authTag' });
        }

        let parsedEncryptedPlainPassword;
        try {
            parsedEncryptedPlainPassword = JSON.parse(encryptedPlainPassword);
            if (!parsedEncryptedPlainPassword.iv || !parsedEncryptedPlainPassword.ciphertext || !parsedEncryptedPlainPassword.authTag) {
                throw new Error('Invalid encryptedPlainPassword format: Missing iv, ciphertext, or authTag');
            }
        } catch (error) {
            console.error('Invalid encryptedPlainPassword format:', error.message);
            return res.status(400).json({ error: 'Invalid encryptedPlainPassword format, must be valid JSON with iv, ciphertext, and authTag' });
        }

        const manager = await User.findById(req.user.id);
        if (!manager) {
            console.error('Manager not found for ID:', req.user.id);
            return res.status(404).json({ error: 'Manager not found' });
        }
        if (!manager.publicKey || !manager.encryptedPrivateKey) {
            console.error('Manager missing publicKey or encryptedPrivateKey:', manager.email);
            return res.status(400).json({ error: 'Manager is missing publicKey or encryptedPrivateKey' });
        }

        const existingEntry = manager.personalPasswordTable.find(
            entry => entry.name === name && entry.website === (website || '')
        );
        if (existingEntry) {
            console.error('Password already exists:', { name, website });
            return res.status(400).json({ error: 'Password with the same name and website already exists' });
        }

        const managerPasswordEntry = {
            name,
            website: website || '',
            username,
            encrypted_password: parsedEncryptedPassword,
            tempAESKey,
            encryptedPlainPassword,
            sharedWith: []
        };

        manager.personalPasswordTable.push(managerPasswordEntry);
        await manager.save();
        console.log('Saved managerPasswordEntry to personalPasswordTable:', {
            name,
            website: website || '',
            username,
            encrypted_password: { ...parsedEncryptedPassword, ciphertext: parsedEncryptedPassword.ciphertext.substring(0, 20) + '...' },
            tempAESKey: tempAESKey.substring(0, 20) + '...',
            encryptedPlainPassword: encryptedPlainPassword.substring(0, 50) + '...'
        });

        let company = await Company.findOne();
        if (!company) {
            company = new Company({ passwordTables: [], Authenticated: [] });
        }
        company.passwordTables.push({
            name,
            website: website || '',
            username,
            encrypted_password: parsedEncryptedPassword
        });
        await company.save();
        console.log('Saved to Company.passwordTables:', { name, website: website || '', username });

        const employees = await User.find({ role: 'employee' });
        console.log('Found employees:', employees.length, 'Employee emails:', employees.map(e => e.email));
        if (employees.length === 0) {
            console.warn('No employees found for sharing password');
            res.status(200).json({
                message: 'Password created but no employees found to share with',
                password: managerPasswordEntry,
                skippedEmployees: []
            });
            return;
        }

        let plainPassword;
        try {
            console.log('Attempting to decrypt plainPassword with tempAESKey:', tempAESKey.substring(0, 20) + '...');
            plainPassword = await decryptWithAES(encryptedPlainPassword, tempAESKey);
            console.log('Decrypted plainPassword successfully');
        } catch (decryptError) {
            console.error('Failed to decrypt plainPassword:', decryptError);
            return res.status(400).json({ error: `Failed to decrypt plainPassword: ${decryptError.message}` });
        }

        let sharedCount = 0;
        const skippedEmployees = [];
        const updatePromises = employees.map(async (employee) => {
            if (!employee.publicKey || !employee.encryptedPrivateKey) {
                console.warn(`Employee ${employee.email} is missing publicKey or encryptedPrivateKey, skipping`);
                skippedEmployees.push({ email: employee.email, reason: 'Missing publicKey or encryptedPrivateKey' });
                return Promise.resolve();
            }

            let employeeEncryptedPassword;
            try {
                console.log(`Encrypting password for employee ${employee.email} with publicKey:`, employee.publicKey.substring(0, 50) + '...');
                employeeEncryptedPassword = await encryptPasswordForSharing(plainPassword, employee.publicKey);
                console.log(`Encrypted password for employee ${employee.email}:`, {
                    ephemeralPublicKey: employeeEncryptedPassword.ephemeralPublicKey.substring(0, 20) + '...',
                    iv: employeeEncryptedPassword.iv,
                    ciphertext: employeeEncryptedPassword.ciphertext.substring(0, 20) + '...',
                    authTag: employeeEncryptedPassword.authTag
                });
            } catch (encryptError) {
                console.error(`Failed to encrypt password for employee ${employee.email}:`, encryptError.message);
                skippedEmployees.push({ email: employee.email, reason: encryptError.message });
                return Promise.resolve();
            }

            const sharedPasswordEntry = {
                name,
                website: website || '',
                username,
                encrypted_password: employeeEncryptedPassword, 
                sharedBy: manager.email
            };

            console.log('Adding to sharedPasswordTable:', {
                email: employee.email,
                sharedPasswordEntry: {
                    name,
                    website: website || '',
                    username,
                    encrypted_password: { ...employeeEncryptedPassword, ciphertext: employeeEncryptedPassword.ciphertext.substring(0, 20) + '...' },
                    sharedBy: manager.email
                }
            });

            employee.sharedPasswordTable.push(sharedPasswordEntry);
            try {
                await employee.save();
                console.log(`Saved sharedPasswordEntry for employee ${employee.email}:`, {
                    name,
                    website: website || '',
                    username,
                    sharedBy: manager.email
                });
                managerPasswordEntry.sharedWith.push(employee.email);
                sharedCount++;
            } catch (saveError) {
                console.error(`Failed to save sharedPasswordEntry for employee ${employee.email}:`, saveError.message);
                skippedEmployees.push({ email: employee.email, reason: `Save failed: ${saveError.message}` });
            }
            return Promise.resolve();
        });

        await Promise.all(updatePromises);

        await manager.save();

        if (skippedEmployees.length > 0) {
            console.warn('Skipped employees:', skippedEmployees);
        }

        console.log(`Password shared with ${sharedCount} employees successfully`);
        res.status(200).json({
            message: `Password created and shared with ${sharedCount} employees successfully`,
            password: managerPasswordEntry,
            skippedEmployees
        });
    } catch (err) {
        console.error('Error adding company password:', err);
        res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
});

module.exports = router;