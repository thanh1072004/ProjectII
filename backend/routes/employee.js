const express = require('express');
const router = express.Router();
const User = require('../models/user');
const { requireAuth } = require('./helper');

router.post('/add-password', requireAuth, async (req, res) => {
    const { name, website, username, encrypted_password } = req.body;

    try {
        console.log('POST /api/employee/add-password called by:', req.user.email);
        console.log('Received request body:', {
            name,
            website,
            username,
            encryptedPassword: typeof encrypted_password === 'string' ? encrypted_password.substring(0, 50) + '...' : encrypted_password
        });

        // Validate input
        if (!name || !username || !encrypted_password) {
            console.error('Missing required fields:', { name, username, hasEncryptedPassword: !!encrypted_password });
            return res.status(400).json({ error: 'Missing required fields: name, username, encrypted_password' });
        }

        // Parse và validate encrypted_password
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

        const user = await User.findById(req.user.id);
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.role !== 'employee') {
            console.error('Unauthorized: User is not an employee:', req.user.email);
            return res.status(403).json({ error: 'Unauthorized: Only employees can use this endpoint' });
        }

        // Kiểm tra xem mật khẩu đã tồn tại chưa
        const existingEntry = user.personalPasswordTable.find(
            entry => entry.name === name && entry.website === (website || '')
        );
        if (existingEntry) {
            console.error('Password already exists:', { name, website });
            return res.status(400).json({ error: 'Password with the same name and website already exists' });
        }

        // Tạo entry mật khẩu
        const passwordEntry = {
            name,
            website: website || '',
            username,
            encrypted_password: parsedEncryptedPassword,
            sharedWith: []
        };

        user.personalPasswordTable.push(passwordEntry);
        await user.save();

        console.log('Password added to personalPasswordTable:', {
            name,
            website: website || '',
            username,
            encrypted_password: { ...parsedEncryptedPassword, ciphertext: parsedEncryptedPassword.ciphertext.substring(0, 20) + '...' }
        });

        res.status(200).json({
            message: 'Password added successfully',
            password: passwordEntry
        });
    } catch (err) {
        console.error('Error adding password:', {
            message: err.message,
            stack: err.stack
        });
        res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
});

router.get('/passwords', requireAuth, async (req, res) => {
    try {
        console.log('GET /api/employee/passwords called by:', req.user.email);
        const user = await User.findById(req.user.id);
        
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }
        
        const passwords = user.personalPasswordTable.map(pwd => ({
            id: pwd._id.toString(),
            name: pwd.name,
            website: pwd.website,
            username: pwd.username,
            encrypted_password: pwd.encrypted_password,
            description: pwd.name
        }));

        console.log('Returning personal passwords:', passwords.length);
        res.json({ passwords });
    } catch (error) {
        console.error('Error fetching passwords:', error);
        res.status(500).json({ error: 'Failed to fetch passwords: ' + error.message });
    }
});

router.get('/all-passwords', requireAuth, async (req, res) => {
    try {
        console.log('GET /api/employee/all-passwords called by:', req.user.email);
        const user = await User.findById(req.user.id);
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        const personalPasswords = user.personalPasswordTable.map(pwd => ({
            id: pwd._id.toString(),
            name: pwd.name,
            website: pwd.website,
            username: pwd.username,
            encrypted_password: pwd.encrypted_password
        }));

        const sharedPasswords = user.sharedPasswordTable.map(pwd => ({
            id: pwd._id.toString(),
            name: pwd.name,
            website: pwd.website,
            username: pwd.username,
            encrypted_password: pwd.encrypted_password,
            sharedBy: pwd.sharedBy
        }));

        console.log('Returning passwords:', {
            personalPasswordsCount: personalPasswords.length,
            sharedPasswordsCount: sharedPasswords.length
        });

        res.json({
            personalPasswords,
            sharedPasswords
        });
    } catch (error) {
        console.error('Error fetching all passwords:', error);
        res.status(500).json({ error: 'Failed to fetch passwords: ' + error.message });
    }
});

router.get('/company-members', requireAuth, async (req, res) => {
    try {
        console.log('GET /api/employee/company-members called by:', req.user.email);
        const users = await User.find({}, 'email role');
        console.log('Returning company members:', users.length);
        res.json({ users });
    } catch (err) {
        console.error('Error fetching company members:', err);
        res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
});

router.get('/users/:email/public-key', requireAuth, async (req, res) => {
    try {
        console.log('GET /api/employee/users/:email/public-key called by:', req.user.email);
        const { email } = req.params;
        const user = await User.findOne({ email }).select('publicKey email');
        
        if (!user) {
            console.error('User not found for email:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (!user.publicKey) {
            console.error('User has no public key:', email);
            return res.status(404).json({ error: 'User has no public key' });
        }
        
        res.json({ 
            email: user.email,
            publicKey: user.publicKey 
        });
    } catch (error) {
        console.error('Error fetching public key:', error);
        res.status(500).json({ error: 'Failed to fetch public key: ' + error.message });
    }
});

router.post('/share-password', requireAuth, async (req, res) => {
    try {
        console.log('POST /api/employee/share-password called by:', req.user.email);
        console.log('Request body:', req.body);
        
        const { 
            recipientEmail, 
            encryptedPasswordData,
            passwordMetadata 
        } = req.body;
        
        console.log('Extracted data:', {
            recipientEmail,
            hasEncryptedData: !!encryptedPasswordData,
            metadata: passwordMetadata
        });
        
        const recipient = await User.findOne({ email: recipientEmail });
        if (!recipient) {
            console.error('Recipient not found:', recipientEmail);
            return res.status(404).json({ error: 'Recipient not found' });
        }

        const sender = await User.findById(req.user.id);
        if (!sender) {
            console.error('Sender not found for ID:', req.user.id);
            return res.status(404).json({ error: 'Sender not found' });
        }

        console.log('Found users:', {
            sender: sender.email,
            recipient: recipient.email
        });

        const { name, website, username, passwordId } = passwordMetadata;
        
        const passwordEntry = sender.personalPasswordTable.id(passwordId);
        if (!passwordEntry) {
            console.error('Password not found for ID:', passwordId);
            return res.status(404).json({ error: 'Password not found' });
        }

        console.log('Found password entry:', {
            id: passwordEntry._id,
            name: passwordEntry.name
        });

        if (!passwordEntry.sharedWith.includes(recipientEmail)) {
            passwordEntry.sharedWith.push(recipientEmail);
        }

        recipient.sharedPasswordTable.push({
            name,
            website,
            username,
            encrypted_password: encryptedPasswordData,
            sharedBy: sender.email
        });

        // Thêm thông báo cho người nhận
        recipient.notifications.push({
            message: `User ${sender.email} shared password ${name} with you`,
            type: 'password_shared',
            senderEmail: sender.email,
            passwordName: name,
            read: false
        });

        console.log('Added to recipient sharedPasswordTable:', { name, website, username, sharedBy: sender.email });
        console.log('Added notification to recipient:', {
            message: `User ${sender.email} shared password ${name} with you`,
            senderEmail: sender.email,
            passwordName: name
        });

        await Promise.all([
            sender.save(),
            recipient.save()
        ]);

        console.log('Users saved successfully');

        res.json({ 
            message: 'Password shared successfully with E2E encryption',
            sharedWith: recipientEmail,
            passwordName: name
        });

    } catch (error) {
        console.error('Error sharing password:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({ error: 'Failed to share password: ' + error.message });
    }
});

router.get('/notifications', requireAuth, async (req, res) => {
    try {
        console.log('GET /api/employee/notifications called by:', req.user.email);
        const user = await User.findById(req.user.id).select('notifications');
        
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        const notifications = user.notifications.map(notification => ({
            id: notification._id,
            message: notification.message,
            type: notification.type,
            senderEmail: notification.senderEmail,
            passwordName: notification.passwordName,
            read: notification.read,
            createdAt: notification.createdAt
        }));

        console.log('Returning notifications:', notifications.length);
        res.json({ notifications });
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ error: 'Failed to fetch notifications: ' + error.message });
    }
});

router.post('/notifications/:id/read', requireAuth, async (req, res) => {
    try {
        console.log('POST /api/employee/notifications/:id/read called by:', req.user.email);
        const { id } = req.params;
        const user = await User.findById(req.user.id);

        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        const notification = user.notifications.id(id);
        if (!notification) {
            console.error('Notification not found for ID:', id);
            return res.status(404).json({ error: 'Notification not found' });
        }

        notification.read = true;
        await user.save();

        console.log('Notification marked as read:', {
            id,
            message: notification.message
        });

        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ error: 'Failed to mark notification as read: ' + error.message });
    }
});

router.delete('/passwords/:id', requireAuth, async (req, res) => {
    try {
        console.log('DELETE /api/employee/passwords/:id called by:', req.user.email);
        const { id } = req.params;
        const user = await User.findById(req.user.id);

        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        // Kiểm tra và xóa từ personalPasswordTable
        const personalPassword = user.personalPasswordTable.id(id);
        if (personalPassword) {
            user.personalPasswordTable.pull(id);
            console.log('Removed personal password:', { id, name: personalPassword.name });

            // Xóa email người dùng khỏi sharedWith của mật khẩu ở các người dùng khác
            const sharedWithUsers = await User.find({ 'personalPasswordTable.sharedWith': user.email });
            for (const sharedUser of sharedWithUsers) {
                const sharedPassword = sharedUser.personalPasswordTable.find(pwd => pwd.sharedWith.includes(user.email));
                if (sharedPassword) {
                    sharedPassword.sharedWith = sharedPassword.sharedWith.filter(email => email !== user.email);
                    await sharedUser.save();
                }
            }

            await user.save();
            return res.json({ message: 'Personal password deleted successfully' });
        }

        // Kiểm tra và xóa từ sharedPasswordTable
        const sharedPassword = user.sharedPasswordTable.id(id);
        if (sharedPassword) {
            user.sharedPasswordTable.pull(id);
            console.log('Removed shared password:', { id, name: sharedPassword.name });
            await user.save();
            return res.json({ message: 'Shared password deleted successfully' });
        }

        console.error('Password not found for ID:', id);
        return res.status(404).json({ error: 'Password not found' });
    } catch (error) {
        console.error('Error deleting password:', error);
        res.status(500).json({ error: 'Failed to delete password: ' + error.message });
    }
});

router.put('/passwords/:id', requireAuth, async (req, res) => {
    try {
        console.log('PUT /api/employee/passwords/:id called by:', req.user.email);
        const { id } = req.params;
        const { name, website, username, encrypted_password } = req.body;

        // Validate input
        if (!name || !username || !encrypted_password) {
            console.error('Missing required fields:', { name, username, hasEncryptedPassword: !!encrypted_password });
            return res.status(400).json({ error: 'Missing required fields: name, username, encrypted_password' });
        }

        // Parse và validate encrypted_password
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

        const user = await User.findById(req.user.id);
        if (!user) {
            console.error('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }

        // Kiểm tra mật khẩu trong personalPasswordTable
        const passwordEntry = user.personalPasswordTable.id(id);
        if (!passwordEntry) {
            console.error('Password not found for ID:', id);
            return res.status(404).json({ error: 'Password not found' });
        }

        // Cập nhật thông tin mật khẩu
        passwordEntry.name = name;
        passwordEntry.website = website || '';
        passwordEntry.username = username;
        passwordEntry.encrypted_password = parsedEncryptedPassword;

        await user.save();

        console.log('Updated password entry:', {
            id,
            name,
            website: website || '',
            username,
            encrypted_password: { ...parsedEncryptedPassword, ciphertext: parsedEncryptedPassword.ciphertext.substring(0, 20) + '...' }
        });

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ error: 'Failed to update password: ' + error.message });
    }
});

module.exports = router;