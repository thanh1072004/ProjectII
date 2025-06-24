const mongoose = require('mongoose')
const { Schema } = mongoose

const passwordEntrySchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    website: {
        type: String,
        trim: true
    },
    username: {
        type: String,
        required: true,
        trim: true
    },
    encrypted_password: {
        type: String,
        required: true
    },
    sharedWith: {
        type: [String],  // Array of email strings
        default: [] 
    }
}, { _id: true });

const sharedPasswordSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    website: {
        type: String,
        trim: true
    },
    username: {
        type: String,
        required: true,
        trim: true
    },
    encrypted_password: {
        type: String,
        required: true
    },
    sharedBy: {
        type: String,
        required: true,
        trim: true
    }
}, { _id: true, timestamps: true });

const userSchema = new Schema({
    role: {
        type: String,
        enum: ['employee', 'manager'],
        default: 'employee',
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    personalPasswordTable: [passwordEntrySchema],
    sharedPasswordTable: [sharedPasswordSchema],
    publicKey: {
        type: String,
        required: true,
    },
    encryptedPrivateKey: {
        type: String,
        required: true,
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('User', userSchema);