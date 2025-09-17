# 🚀 Astro Auth - Full-Stack Authentication System

A modern, secure authentication system built with Node.js, Express, and PostgreSQL, featuring both manual registration/login and Google OAuth integration. The application includes a beautiful cosmic-themed UI with user reviews functionality.

## ✨ Features

- **🔐 Dual Authentication Methods**
  - Manual registration and login with email/password
  - Google OAuth 2.0 integration
  - JWT token-based authentication

- **👤 User Management**
  - User profiles with profile pictures
  - Secure password hashing with bcrypt
  - Session management

- **⭐ Reviews System**
  - Create, read, update, and delete reviews
  - Star ratings (1-5 scale)
  - User-specific review management
  - Pagination support

- **🎨 Modern UI**
  - Responsive cosmic-themed design
  - Animated starfield background
  - Interactive chat interface
  - Mobile-friendly layout

## 🛠️ Tech Stack

- **Backend:** Node.js, Express.js
- **Database:** PostgreSQL
- **Authentication:** Passport.js, JWT, bcrypt
- **Frontend:** Vanilla HTML, CSS, JavaScript
- **OAuth:** Google OAuth 2.0

## 📋 Prerequisites

Before running this application, make sure you have:

- Node.js (v14 or higher)
- PostgreSQL database
- Google OAuth credentials (Client ID and Secret)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone <your-repository-url>
   cd astro-auth
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up PostgreSQL database**
   - Create a database named `astro_auth`
   - The application will automatically create the required tables on startup

4. **Configure environment variables**
   
   Create a `.env` file in the root directory with the following variables:
   ```env
   # Server Configuration
   PORT=5500
   
   # PostgreSQL Database Configuration
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=astro_auth
   DB_USER=postgres
   DB_PASSWORD=your_password_here
   
   # JWT Configuration
   JWT_SECRET=your_jwt_secret_here
   
   # Google OAuth Configuration
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   
   # Session Secret
   SESSION_SECRET=your_session_secret_here
   ```

5. **Get Google OAuth Credentials**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add `http://localhost:5500/auth/google/callback` to authorized redirect URIs

## 🏃‍♂️ Running the Application

1. **Start the server**
   ```bash
   node server.js
   ```

2. **Access the application**
   - Open your browser and navigate to `http://localhost:5500`
   - The server will automatically create database tables on first run

## 📚 API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `GET /auth/google` - Google OAuth login
- `GET /auth/google/callback` - Google OAuth callback
- `POST /api/logout` - User logout

### User Management
- `GET /api/profile` - Get user profile (protected)

### Reviews
- `GET /api/reviews` - Get all reviews (with pagination)
- `POST /api/reviews` - Create a new review (protected)
- `PUT /api/reviews/:id` - Update a review (protected)
- `DELETE /api/reviews/:id` - Delete a review (protected)

### Pages
- `GET /` - Landing page
- `GET /home` - User dashboard (protected)
- `GET /chat` - Chat interface (protected)

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    google_id VARCHAR(255) UNIQUE,
    profile_picture VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Reviews Table
```sql
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    text TEXT NOT NULL,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔒 Security Features

- **Password Security:** Passwords are hashed using bcrypt with salt rounds
- **JWT Tokens:** Secure token-based authentication with 24-hour expiration
- **Input Validation:** Server-side validation for all user inputs
- **SQL Injection Prevention:** Parameterized queries using PostgreSQL
- **CORS Protection:** Configured CORS for secure cross-origin requests
- **Environment Variables:** Sensitive data stored in environment variables

## 🎨 UI Features

- **Responsive Design:** Works seamlessly on desktop and mobile devices
- **Animated Background:** Beautiful starfield animation with twinkling stars
- **Modern Typography:** Clean, readable fonts with proper contrast
- **Interactive Elements:** Smooth hover effects and transitions
- **User Feedback:** Clear success/error messages for all actions

## 🚀 Deployment

### Environment Setup for Production
1. Set `NODE_ENV=production` in your environment
2. Use a secure JWT secret (generate with `openssl rand -hex 64`)
3. Configure proper database credentials
4. Set up HTTPS and update CORS origins
5. Use environment-specific Google OAuth credentials

### Recommended Hosting Platforms
- **Backend:** Heroku, Railway, DigitalOcean
- **Database:** Heroku Postgres, AWS RDS, DigitalOcean Managed Databases

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure PostgreSQL is running
   - Check database credentials in `.env`
   - Verify database exists

2. **Google OAuth Not Working**
   - Check Google OAuth credentials
   - Verify redirect URI in Google Console
   - Ensure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set

3. **JWT Token Issues**
   - Verify JWT_SECRET is set in environment
   - Check token expiration (24 hours default)
   - Clear browser localStorage if needed

4. **Port Already in Use**
   - Change PORT in `.env` file
   - Kill existing processes on port 5500

## 📞 Support

If you encounter any issues or have questions, please:
1. Check the troubleshooting section above
2. Review the console logs for error messages
3. Open an issue on GitHub with detailed information

---

**Built with ❤️ using Node.js and PostgreSQL**
