const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const { Pool } = require('pg');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();

// ===== CONFIGURATION =====
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key-change-in-production';
const JWT_SECRET_2FA = process.env.JWT_SECRET_2FA || 'your-2fa-jwt-secret';

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/auth/', limiter);

// ===== UTILITIES =====
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
};

const generateVerificationCode = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendEmail = async (to, subject, html) => {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: true,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });

    await transporter.sendMail({
        from: `"CryptoSense" <${process.env.SMTP_USER}>`,
        to,
        subject,
        html
    });
};

// ===== DATABASE INITIALIZATION =====
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            avatar_url VARCHAR(500),
            balance DECIMAL(15,2) DEFAULT 0.00,
            email_verified BOOLEAN DEFAULT FALSE,
            verification_code VARCHAR(10),
            verification_expires TIMESTAMP,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            two_factor_secret VARCHAR(500),
            role VARCHAR(20) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS investments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            cryptocurrency VARCHAR(50) NOT NULL,
            amount_invested DECIMAL(15,2) NOT NULL,
            current_value DECIMAL(15,2) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS deposits (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            amount DECIMAL(15,2) NOT NULL,
            wallet_address VARCHAR(255) NOT NULL,
            cryptocurrency VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type VARCHAR(50) NOT NULL,
            amount DECIMAL(15,2) NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log('Database initialized');
}

// ===== MIDDLEWARE FUNCTIONS =====
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// ===== ROUTES =====

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ===== AUTH ROUTES =====

// Signup
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate verification code
        const verificationCode = generateVerificationCode();
        const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        // Create user
        const result = await pool.query(
            `INSERT INTO users (name, email, password, verification_code, verification_expires)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, email, role, email_verified`,
            [name, email, hashedPassword, verificationCode, verificationExpires]
        );

        const user = result.rows[0];

        // Send verification email
        const verificationUrl = `${process.env.FRONTEND_URL}/verify?code=${verificationCode}`;
        const emailHtml = `
            <h2>Welcome to CryptoSense!</h2>
            <p>Thank you for signing up. Please verify your email address by entering this code:</p>
            <h1 style="text-align: center; letter-spacing: 10px; margin: 30px 0;">${verificationCode}</h1>
            <p>Or click <a href="${verificationUrl}">here</a> to verify.</p>
            <p>This code will expire in 24 hours.</p>
        `;

        await sendEmail(email, 'Verify your CryptoSense account', emailHtml);

        res.status(201).json({
            message: 'Account created. Please check your email for verification.',
            user
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify Email
app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const { code } = req.body;

        const result = await pool.query(
            `SELECT id, email, verification_expires FROM users 
             WHERE verification_code = $1 AND email_verified = FALSE`,
            [code]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        const user = result.rows[0];

        if (new Date(user.verification_expires) < new Date()) {
            return res.status(400).json({ message: 'Verification code has expired' });
        }

        // Mark email as verified
        await pool.query(
            'UPDATE users SET email_verified = TRUE, verification_code = NULL WHERE id = $1',
            [user.id]
        );

        res.json({
            message: 'Email verified successfully',
            requires2FASetup: true // Prompt user to setup 2FA
        });

    } catch (error) {
        console.error('Verify email error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Resend verification
app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await pool.query(
            'SELECT id, email_verified FROM users WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userResult.rows[0];

        if (user.email_verified) {
            return res.status(400).json({ message: 'Email already verified' });
        }

        // Generate new verification code
        const verificationCode = generateVerificationCode();
        const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

        await pool.query(
            'UPDATE users SET verification_code = $1, verification_expires = $2 WHERE id = $3',
            [verificationCode, verificationExpires, user.id]
        );

        // Send email
        const emailHtml = `
            <h2>CryptoSense Verification Code</h2>
            <p>Your new verification code is:</p>
            <h1 style="text-align: center; letter-spacing: 10px; margin: 30px 0;">${verificationCode}</h1>
            <p>This code will expire in 24 hours.</p>
        `;

        await sendEmail(email, 'Your CryptoSense Verification Code', emailHtml);

        res.json({ message: 'Verification code sent' });

    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Check if email is verified
        if (!user.email_verified) {
            return res.status(403).json({ message: 'Please verify your email first' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // If 2FA is enabled, require 2FA verification
        if (user.two_factor_enabled) {
            const tempToken = jwt.sign(
                { id: user.id, requires2FA: true },
                JWT_SECRET_2FA,
                { expiresIn: '5m' }
            );

            return res.json({
                requires2FA: true,
                tempToken,
                message: '2FA verification required'
            });
        }

        // Generate JWT token
        const token = generateToken(user);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatar: user.avatar_url,
                balance: user.balance,
                role: user.role,
                two_factor_enabled: user.two_factor_enabled
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 2FA Verification for login
app.post('/api/auth/2fa/login', async (req, res) => {
    try {
        const { code, tempToken } = req.body;

        // Verify temp token
        let decoded;
        try {
            decoded = jwt.verify(tempToken, JWT_SECRET_2FA);
        } catch (error) {
            return res.status(401).json({ message: 'Invalid or expired token' });
        }

        const userId = decoded.id;

        // Get user and 2FA secret
        const result = await pool.query(
            'SELECT * FROM users WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = result.rows[0];

        // Verify 2FA code
        const verified = speakeasy.totp.verify({
            secret: user.two_factor_secret,
            encoding: 'base32',
            token: code,
            window: 1
        });

        if (!verified) {
            return res.status(401).json({ message: 'Invalid 2FA code' });
        }

        // Generate final JWT token
        const token = generateToken(user);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatar: user.avatar_url,
                balance: user.balance,
                role: user.role,
                two_factor_enabled: user.two_factor_enabled
            }
        });

    } catch (error) {
        console.error('2FA login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 2FA Setup
app.post('/api/auth/2fa/setup', authenticateToken, async (req, res) => {
    try {
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `CryptoSense:${req.user.email}`
        });

        // Generate QR code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        // Store secret temporarily (user needs to verify first)
        await pool.query(
            'UPDATE users SET two_factor_secret = $1 WHERE id = $2',
            [secret.base32, req.user.id]
        );

        res.json({
            secret: secret.base32,
            qrCode
        });

    } catch (error) {
        console.error('2FA setup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify and enable 2FA
app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;

        // Get user secret
        const result = await pool.query(
            'SELECT two_factor_secret FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const secret = result.rows[0].two_factor_secret;

        // Verify code
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 1
        });

        if (!verified) {
            return res.status(400).json({ message: 'Invalid 2FA code' });
        }

        // Enable 2FA
        await pool.query(
            'UPDATE users SET two_factor_enabled = TRUE WHERE id = $1',
            [req.user.id]
        );

        res.json({ message: '2FA enabled successfully' });

    } catch (error) {
        console.error('2FA verify error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Disable 2FA
app.post('/api/auth/2fa/disable', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL WHERE id = $1',
            [req.user.id]
        );

        res.json({ message: '2FA disabled successfully' });

    } catch (error) {
        console.error('Disable 2FA error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            // Don't reveal if user exists
            return res.json({ message: 'If an account exists, a reset link has been sent' });
        }

        const user = userResult.rows[0];

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        // Store reset token
        await pool.query(
            'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, resetToken, expiresAt]
        );

        // Send reset email
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        const emailHtml = `
            <h2>Reset Your Password</h2>
            <p>Click the link below to reset your password:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
        `;

        await sendEmail(email, 'Reset Your CryptoSense Password', emailHtml);

        res.json({ message: 'Password reset instructions sent' });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;

        // Find valid reset token
        const resetResult = await pool.query(
            `SELECT pr.user_id, pr.expires_at 
             FROM password_resets pr
             JOIN users u ON pr.user_id = u.id
             WHERE pr.token = $1 AND pr.used = FALSE AND pr.expires_at > NOW()`,
            [token]
        );

        if (resetResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        const { user_id, expires_at } = resetResult.rows[0];

        if (new Date(expires_at) < new Date()) {
            return res.status(400).json({ message: 'Reset token has expired' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update password
        await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [hashedPassword, user_id]
        );

        // Mark reset token as used
        await pool.query(
            'UPDATE password_resets SET used = TRUE WHERE token = $1',
            [token]
        );

        res.json({ message: 'Password reset successful' });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== USER ROUTES =====

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, avatar_url, balance, role, two_factor_enabled FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user: result.rows[0] });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { name, email } = req.body;

        // Check if email is already taken
        if (email !== req.user.email) {
            const existingUser = await pool.query(
                'SELECT id FROM users WHERE email = $1 AND id != $2',
                [email, req.user.id]
            );

            if (existingUser.rows.length > 0) {
                return res.status(400).json({ message: 'Email already in use' });
            }
        }

        await pool.query(
            'UPDATE users SET name = $1, email = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
            [name, email, req.user.id]
        );

        res.json({ message: 'Profile updated successfully' });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Upload avatar
const upload = multer({ dest: 'uploads/' });
app.post('/api/user/avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
    try {
        // In production, upload to cloud storage (AWS S3, Cloudinary, etc.)
        // For now, just store the file path
        const avatarUrl = `/uploads/${req.file.filename}`;

        await pool.query(
            'UPDATE users SET avatar_url = $1 WHERE id = $2',
            [avatarUrl, req.user.id]
        );

        res.json({ avatarUrl });

    } catch (error) {
        console.error('Upload avatar error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Change password
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Get current password
        const result = await pool.query(
            'SELECT password FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = result.rows[0];

        // Verify current password
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [hashedPassword, req.user.id]
        );

        res.json({ message: 'Password changed successfully' });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user balance
app.get('/api/user/balance', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT balance FROM users WHERE id = $1',
            [req.user.id]
        );

        res.json({ balance: result.rows[0].balance });

    } catch (error) {
        console.error('Get balance error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== INVESTMENT ROUTES =====

// Get investments
app.get('/api/investments', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM investments WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );

        res.json(result.rows);

    } catch (error) {
        console.error('Get investments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get portfolio analytics
app.get('/api/investments/analytics', authenticateToken, async (req, res) => {
    try {
        // Mock analytics data - in production, calculate from real data
        const analytics = {
            totalInvested: 45000,
            currentValue: 51289.50,
            monthlyReturns: 6539.50,
            roi: 16.8,
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            data: [10000, 12000, 11000, 15000, 18000, 20000]
        };

        res.json(analytics);

    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== DEPOSIT ROUTES =====

// Create deposit
app.post('/api/deposits', authenticateToken, async (req, res) => {
    try {
        const { amount, cryptocurrency, wallet_address } = req.body;

        // Generate a real wallet address (in production, use your payment processor)
        const generatedAddress = wallet_address || `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`;

        const result = await pool.query(
            `INSERT INTO deposits (user_id, amount, cryptocurrency, wallet_address)
             VALUES ($1, $2, $3, $4)
             RETURNING *`,
            [req.user.id, amount, cryptocurrency, generatedAddress]
        );

        // Update user balance
        await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [amount, req.user.id]
        );

        // Log transaction
        await pool.query(
            'INSERT INTO transactions (user_id, type, amount, description) VALUES ($1, $2, $3, $4)',
            [req.user.id, 'deposit', amount, `Deposit via ${cryptocurrency}`]
        );

        res.status(201).json(result.rows[0]);

    } catch (error) {
        console.error('Create deposit error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== ADMIN ROUTES =====

// Get all users
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, balance, role, email_verified, created_at FROM users ORDER BY created_at DESC'
        );

        res.json(result.rows);

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user
app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, balance, role } = req.body;

        const updateFields = [];
        const values = [];
        let paramCount = 1;

        if (name !== undefined) {
            updateFields.push(`name = $${paramCount}`);
            values.push(name);
            paramCount++;
        }

        if (balance !== undefined) {
            updateFields.push(`balance = $${paramCount}`);
            values.push(balance);
            paramCount++;
        }

        if (role !== undefined) {
            updateFields.push(`role = $${paramCount}`);
            values.push(role);
            paramCount++;
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ message: 'No fields to update' });
        }

        values.push(id);

        const query = `
            UPDATE users 
            SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP
            WHERE id = $${paramCount}
            RETURNING id, name, email, balance, role
        `;

        const result = await pool.query(query, values);

        res.json({
            message: 'User updated successfully',
            user: result.rows[0]
        });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get platform statistics
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Get total users
        const usersResult = await pool.query('SELECT COUNT(*) as count FROM users');
        const totalUsers = parseInt(usersResult.rows[0].count);

        // Get total deposits
        const depositsResult = await pool.query('SELECT SUM(amount) as total FROM deposits WHERE status = $1', ['completed']);
        const totalDeposits = parseFloat(depositsResult.rows[0].total || 0);

        // Get total platform balance
        const balanceResult = await pool.query('SELECT SUM(balance) as total FROM users');
        const totalBalance = parseFloat(balanceResult.rows[0].total || 0);

        res.json({
            totalUsers,
            totalDeposits,
            totalBalance,
            activeUsers: Math.floor(totalUsers * 0.7) // Mock active users
        });

    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;

async function startServer() {
    await initDB();
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`API: http://localhost:${PORT}/api`);
        console.log(`Health check: http://localhost:${PORT}/api/health`);
    });
}

startServer();
