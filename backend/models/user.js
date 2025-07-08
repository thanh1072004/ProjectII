const mongoose = require('mongoose');
const { Schema } = mongoose;

// Schema cho thông báo
const notificationSchema = new Schema({
    message: {
        type: String,
        required: true,
        trim: true,
        maxlength: [200, 'Notification message cannot exceed 200 characters']
    },
    type: {
        type: String,
        enum: ['password_shared'],
        required: true
    },
    senderEmail: {
        type: String,
        required: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/, 'Invalid email format for senderEmail']
    },
    passwordName: {
        type: String,
        required: true,
        trim: true
    },
    read: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { _id: true });

// Schema cho mật khẩu cá nhân (personalPasswordTable)
const passwordEntrySchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: [1, 'Name must be at least 1 character long'],
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    website: {
        type: String,
        trim: true,
        match: [/^(https?:\/\/)?([\w-]+(\.[\w-]+)+)([/?].*)?$|^$/, 'Invalid website URL'],
        default: ''
    },
    username: {
        type: String,
        required: true,
        trim: true,
        minlength: [1, 'Username must be at least 1 character long'],
        maxlength: [100, 'Username cannot exceed 100 characters']
    },
    encrypted_password: {
        type: Object,
        required: true,
        validate: {
            validator: function (value) {
                return value && typeof value === 'object' &&
                    value.ephemeralPublicKey && typeof value.ephemeralPublicKey === 'string' &&
                    value.iv && typeof value.iv === 'string' &&
                    value.ciphertext && typeof value.ciphertext === 'string' &&
                    value.authTag && typeof value.authTag === 'string';
            },
            message: 'Invalid encrypted_password format. Must contain ephemeralPublicKey, iv, ciphertext, and authTag as strings.'
        }
    },
    tempAESKey: {
        type: String,
        required: function () { return this.parent().role === 'manager'; },
        validate: {
            validator: function (value) {
                if (this.parent().role !== 'manager') return true;
                return value && /^[A-Za-z0-9+/=]+$/.test(value);
            },
            message: 'Invalid tempAESKey format. Must be a valid base64 string.'
        }
    },
    encryptedPlainPassword: {
        type: String,
        required: function () { return this.parent().role === 'manager'; },
        validate: {
            validator: function (value) {
                if (this.parent().role !== 'manager') return true;
                try {
                    JSON.parse(value);
                    return true;
                } catch {
                    return false;
                }
            },
            message: 'Invalid encryptedPlainPassword format. Must be a valid JSON string.'
        }
    },
    sharedWith: {
        type: [String],
        default: [],
        validate: {
            validator: function (emails) {
                return emails.every(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email === 'thanhkudo@123');
            },
            message: 'Invalid email in sharedWith array.'
        }
    }
}, { _id: true });

// Schema cho mật khẩu được chia sẻ (sharedPasswordTable)
const sharedPasswordSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: [1, 'Name must be at least 1 character long'],
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    website: {
        type: String,
        trim: true,
        match: [/^(https?:\/\/)?([\w-]+(\.[\w-]+)+)([/?].*)?$|^$/, 'Invalid website URL'],
        default: ''
    },
    username: {
        type: String,
        required: true,
        trim: true,
        minlength: [1, 'Username must be at least 1 character long'],
        maxlength: [100, 'Username cannot exceed 100 characters']
    },
    encrypted_password: {
        type: Object,
        required: true,
        validate: {
            validator: function (value) {
                return value && typeof value === 'object' &&
                    value.ephemeralPublicKey && typeof value.ephemeralPublicKey === 'string' &&
                    value.iv && typeof value.iv === 'string' &&
                    value.ciphertext && typeof value.ciphertext === 'string' &&
                    value.authTag && typeof value.authTag === 'string';
            },
            message: 'Invalid encrypted_password format. Must contain ephemeralPublicKey, iv, ciphertext, and authTag as strings.'
        }
    },
    sharedBy: {
        type: String,
        required: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/, 'Invalid email format for sharedBy']
    }
}, { _id: true, timestamps: true });

// Schema cho mã xác thực
const verificationCodeSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/, 'Invalid email format']
    },
    code: {
        type: String,
        required: true,
        minlength: [6, 'Code must be 6 digits'],
        maxlength: [6, 'Code must be 6 digits']
    },
    userData: {
        email: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/, 'Invalid email format']
        },
        role: {
            type: String,
            enum: ['employee', 'manager'],
            required: true
        },
        publicKey: {
            type: String,
            required: true,
            validate: {
                validator: function (value) {
                    return /^[A-Za-z0-9+/=]+$/.test(value);
                },
                message: 'Invalid publicKey format. Must be a valid base64 string.'
            }
        },
        encryptedPrivateKey: {
            type: Schema.Types.Mixed,
            required: true,
            validate: {
                validator: function (value) {
                    return value && typeof value === 'object' &&
                        value.salt && typeof value.salt === 'string' &&
                        value.iv && typeof value.iv === 'string' &&
                        value.ciphertext && typeof value.ciphertext === 'string' &&
                        value.authTag && typeof value.authTag === 'string';
                },
                message: 'Invalid encryptedPrivateKey format. Must contain salt, iv, ciphertext, and authTag as strings.'
            }
        },
        hashedPassword: {
            type: String,
            required: true
        }
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: '15m' // Mã hết hạn sau 15 phút
    }
});

// Schema chính cho User
const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$|^thanhkudo@123$/, 'Invalid email format'],
        maxlength: [100, 'Email cannot exceed 100 characters']
    },
    password: {
        type: String,
        required: true,
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        enum: ['employee', 'manager'],
        required: true,
        default: 'employee'
    },
    publicKey: {
        type: String,
        required: true,
        validate: {
            validator: function (value) {
                return /^[A-Za-z0-9+/=]+$/.test(value);
            },
            message: 'Invalid publicKey format. Must be a valid base64 string.'
        }
    },
    encryptedPrivateKey: {
        type: Schema.Types.Mixed,
        required: true,
        set: function (value) {
            if (typeof value === 'string') {
                try {
                    return JSON.parse(value);
                } catch (err) {
                    throw new Error('Invalid encryptedPrivateKey format: Failed to parse JSON');
                }
            }
            return value;
        },
        validate: {
            validator: function (value) {
                return value && typeof value === 'object' &&
                    value.salt && typeof value.salt === 'string' &&
                    value.iv && typeof value.iv === 'string' &&
                    value.ciphertext && typeof value.ciphertext === 'string' &&
                    value.authTag && typeof value.authTag === 'string';
            },
            message: 'Invalid encryptedPrivateKey format. Must contain salt, iv, ciphertext, and authTag as strings.'
        }
    },
    personalPasswordTable: [passwordEntrySchema],
    sharedPasswordTable: [sharedPasswordSchema],
    notifications: [notificationSchema]
}, {
    timestamps: true
});

// Thêm indexes để tối ưu hóa tìm kiếm
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ role: 1 });

const User = mongoose.model('User', userSchema);
const VerificationCode = mongoose.model('VerificationCode', verificationCodeSchema);

// Export User làm default, VerificationCode làm named export
module.exports = User;
module.exports.VerificationCode = VerificationCode;