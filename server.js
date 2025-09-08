const express = require('express');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: 'http://localhost:5500', // Your frontend URL
    credentials: true
}));
app.use(express.json());
app.use(express.static('public')); // Serve your HTML file from public folder
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL connection
const pool = new pg.Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'astro_auth',
    password: process.env.DB_PASSWORD || 'password',
    port: process.env.DB_PORT || 5432,
});

// Create tables if they don't exist
const createTables = async () => {
    try {
        // Users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(255),
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE,
                password_hash VARCHAR(255),
                google_id VARCHAR(255) UNIQUE,
                profile_picture VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Reviews table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                user_name VARCHAR(255) NOT NULL,
                title VARCHAR(255) NOT NULL,
                text TEXT NOT NULL,
                rating INTEGER CHECK (rating >= 1 AND rating <= 5) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables created/verified successfully');
    } catch (err) {
        console.error('Error creating database tables:', err);
    }
};

// Initialize database
createTables();

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE google_id = $1 OR email = $2',
            [profile.id, profile.emails[0].value]
        );

        if (existingUser.rows.length > 0) {
            return done(null, existingUser.rows[0]);
        }

        // Create new user
        const newUser = await pool.query(`
            INSERT INTO users (full_name, email, google_id, profile_picture, username)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `, [
            profile.displayName,
            profile.emails[0].value,
            profile.id,
            profile.photos[0].value,
            profile.emails[0].value.split('@')[0] // Use email prefix as username
        ]);

        return done(null, newUser.rows[0]);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, user.rows[0]);
    } catch (error) {
        done(error, null);
    }
});

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Manual Registration
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, username, password } = req.body;

        // Validate input
        if (!fullName || !email || !username || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );

        if (existingUser.rows.length > 0) {
            const existing = existingUser.rows[0];
            if (existing.email === email) {
                return res.status(400).json({ error: 'Email already registered' });
            }
            if (existing.username === username) {
                return res.status(400).json({ error: 'Username already taken' });
            }
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert new user
        const newUser = await pool.query(`
            INSERT INTO users (full_name, email, username, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING id, full_name, email, username, created_at
        `, [fullName, email, username, passwordHash]);

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: newUser.rows[0].id, 
                email: newUser.rows[0].email,
                username: newUser.rows[0].username
            },
            process.env.JWT_SECRET || 'your-jwt-secret',
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser.rows[0],
            token: token
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Manual Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user by email
        const user = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const foundUser = user.rows[0];

        // Check if user registered with Google (no password)
        if (!foundUser.password_hash) {
            return res.status(401).json({ error: 'Please sign in with Google' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, foundUser.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: foundUser.id, 
                email: foundUser.email,
                username: foundUser.username
            },
            process.env.JWT_SECRET || 'your-jwt-secret',
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            user: {
                id: foundUser.id,
                full_name: foundUser.full_name,
                email: foundUser.email,
                username: foundUser.username,
                profile_picture: foundUser.profile_picture,
                created_at: foundUser.created_at
            },
            token: token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Google OAuth routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/?error=google_auth_failed' }),
    async (req, res) => {
        try {
            // Generate JWT token for Google user
            const token = jwt.sign(
                { 
                    id: req.user.id, 
                    email: req.user.email,
                    username: req.user.username
                },
                process.env.JWT_SECRET || 'your-jwt-secret',
                { expiresIn: '24h' }
            );

            // Redirect to home page with token
            res.redirect(`/home?token=${token}&user=${encodeURIComponent(JSON.stringify({
                id: req.user.id,
                full_name: req.user.full_name,
                email: req.user.email,
                username: req.user.username,
                profile_picture: req.user.profile_picture
            }))}`);
        } catch (error) {
            console.error('Google callback error:', error);
            res.redirect('/?error=auth_failed');
        }
    }
);

// Protected route - User profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await pool.query(
            'SELECT id, full_name, email, username, profile_picture, created_at FROM users WHERE id = $1',
            [req.user.id]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: user.rows[0] });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Reviews API routes
app.get('/api/reviews', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;

        const reviews = await pool.query(`
            SELECT r.*, u.profile_picture 
            FROM reviews r
            LEFT JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        const totalCount = await pool.query('SELECT COUNT(*) FROM reviews');
        const total = parseInt(totalCount.rows[0].count);

        res.json({
            reviews: reviews.rows,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Reviews fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create review
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, title, text } = req.body;

        // Validate input
        if (!rating || !title || !text) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        // Get user info
        const userResult = await pool.query(
            'SELECT full_name, username FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        const userName = user.full_name || user.username;

        // Check if user already has a review (optional - remove if multiple reviews allowed)
        const existingReview = await pool.query(
            'SELECT id FROM reviews WHERE user_id = $1',
            [req.user.id]
        );

        if (existingReview.rows.length > 0) {
            return res.status(400).json({ error: 'You have already submitted a review' });
        }

        // Insert review
        const newReview = await pool.query(`
            INSERT INTO reviews (user_id, user_name, title, text, rating)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `, [req.user.id, userName, title, text, rating]);

        res.status(201).json({
            message: 'Review submitted successfully',
            review: newReview.rows[0]
        });

    } catch (error) {
        console.error('Review submission error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update review
app.put('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const reviewId = req.params.id;
        const { rating, title, text } = req.body;

        // Validate input
        if (!rating || !title || !text) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        // Check if review exists and belongs to user
        const existingReview = await pool.query(
            'SELECT * FROM reviews WHERE id = $1 AND user_id = $2',
            [reviewId, req.user.id]
        );

        if (existingReview.rows.length === 0) {
            return res.status(404).json({ error: 'Review not found or unauthorized' });
        }

        // Update review
        const updatedReview = await pool.query(`
            UPDATE reviews 
            SET title = $1, text = $2, rating = $3, updated_at = CURRENT_TIMESTAMP
            WHERE id = $4 AND user_id = $5
            RETURNING *
        `, [title, text, rating, reviewId, req.user.id]);

        res.json({
            message: 'Review updated successfully',
            review: updatedReview.rows[0]
        });

    } catch (error) {
        console.error('Review update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete review
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const reviewId = req.params.id;

        // Check if review exists and belongs to user
        const existingReview = await pool.query(
            'SELECT * FROM reviews WHERE id = $1 AND user_id = $2',
            [reviewId, req.user.id]
        );

        if (existingReview.rows.length === 0) {
            return res.status(404).json({ error: 'Review not found or unauthorized' });
        }

        // Delete review
        await pool.query('DELETE FROM reviews WHERE id = $1 AND user_id = $2', [reviewId, req.user.id]);

        res.json({ message: 'Review deleted successfully' });

    } catch (error) {
        console.error('Review deletion error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Home page (protected) - Now serves the new homepage
app.get('/home', (req, res) => {
    res.sendFile(__dirname + '/public/home.html');
});

// Chat page (protected) - Serves the chatbot interface
app.get('/chat', (req, res) => {
    res.sendFile(__dirname + '/public/chat.html');
});

// Logout route
app.post('/api/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 5500;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Frontend available at: http://localhost:${PORT}`);
    console.log(`API endpoints:`);
    console.log(`- POST /api/register - User registration`);
    console.log(`- POST /api/login - User login`);
    console.log(`- GET /api/profile - User profile (protected)`);
    console.log(`- GET /api/reviews - Get reviews`);
    console.log(`- POST /api/reviews - Create review (protected)`);
    console.log(`- PUT /api/reviews/:id - Update review (protected)`);
    console.log(`- DELETE /api/reviews/:id - Delete review (protected)`);
    console.log(`- GET /auth/google - Google OAuth`);
    console.log(`- POST /api/logout - Logout`);
});