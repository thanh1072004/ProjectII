//TODO: Add employee backend
/*
    - Create password for personal.
    - Send request to fetch password from the company 
    - In Request password section, employee able to see all of the password of that company and then click the domain if want to know password.
*/
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const { requireAuth } = require('./helper')

router.post('/employee/add-password', requireAuth, async (req, res) => {
    const { name, website, username, encrypted_password } = req.body;
    
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.personalPasswordTable.push({
            name,
            website,
            username,
            encrypted_password,
            sharedWith: []
        });

        await user.save();

        res.status(200).json({
            message: 'Password added successfully',
            password: user.personalPasswordTable[user.personalPasswordTable.length - 1]
        });
    } catch (err) {
        console.error('Error adding password:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/employee/passwords', requireAuth, async (req, res) => {
    
    try {
        const user = await User.findById(req.user.id);
        
        if (!user) {
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

        res.json({ passwords });
    } catch (error) {
        console.error('Error fetching passwords:', error);
        res.status(500).json({ error: 'Failed to fetch passwords' });
    }
});

router.get('/employee/all-passwords', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
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

        res.json({
            personalPasswords,
            sharedPasswords
        });
    } catch (error) {
        console.error('Error fetching passwords:', error);
        res.status(500).json({ error: 'Failed to fetch passwords' });
    }
});

router.get('/company-members', requireAuth, async (req, res) => {
    try {
        const users = await User.find({}, 'email role'); // add 'name' if you have it
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/users/:email/public-key', requireAuth, async (req, res) => {
    try {
        const { email } = req.params;
        const user = await User.findOne({ email }).select('publicKey email');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (!user.publicKey) {
            return res.status(404).json({ error: 'User has no public key' });
        }
        
        res.json({ 
            email: user.email,
            publicKey: user.publicKey 
        });
    } catch (error) {
        console.error('Error fetching public key:', error);
        res.status(500).json({ error: 'Failed to fetch public key' });
    }
});

router.post('/employee/share-password', requireAuth, async (req, res) => {
    try {
        console.log('=== Share Password Backend Debug ===');
        console.log('Request body:', req.body);
        
        const { 
            recipientEmail, 
            encryptedPasswordData,  // Changed from encryptedPassword
            passwordMetadata 
        } = req.body;
        
        console.log('Extracted data:', {
            recipientEmail,
            hasEncryptedData: !!encryptedPasswordData,
            metadata: passwordMetadata
        });
        
        // Find recipient and validate
        const recipient = await User.findOne({ email: recipientEmail });
        if (!recipient) {
            return res.status(404).json({ error: 'Recipient not found' });
        }

        // Find sender
        const sender = await User.findById(req.user.id);
        if (!sender) {
            return res.status(404).json({ error: 'Sender not found' });
        }

        console.log('Found users:', {
            sender: sender.email,
            recipient: recipient.email
        });

        // Extract metadata
        const { name, website, username, passwordId } = passwordMetadata;
        
        // Find the password entry to update sharedWith
        const passwordEntry = sender.personalPasswordTable.id(passwordId);
        if (!passwordEntry) {
            return res.status(404).json({ error: 'Password not found' });
        }

        console.log('Found password entry:', {
            id: passwordEntry._id,
            name: passwordEntry.name
        });

        // Add recipient email to sharedWith if not already present
        if (!passwordEntry.sharedWith.includes(recipientEmail)) {
            passwordEntry.sharedWith.push(recipientEmail);
        }

        // Add to recipient's sharedPasswordTable
        recipient.sharedPasswordTable.push({
            name,
            website,
            username,
            encrypted_password: encryptedPasswordData, // This is the E2E encrypted data
            sharedBy: sender.email
        });

        console.log('Added to recipient shared table');

        // Save both users
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
        console.error('Error sharing password:', error);
        res.status(500).json({ error: 'Failed to share password' });
    }
});


module.exports = router;