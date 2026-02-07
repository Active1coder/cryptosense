# CryptoSense Investment Platform

A complete cryptocurrency investment platform with user authentication, portfolio management, and admin controls.

## Features
- User signup/login with email verification
- Two-factor authentication (2FA)
- Password reset functionality
- Investment portfolio dashboard
- Real-time crypto prices
- Admin user management
- Secure wallet deposits

## Quick Start

### 1. Prerequisites
- Node.js 16+ installed
- PostgreSQL database
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/cryptosense.git
cd cryptosense

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env file with your database credentials

# Initialize database
# Run this in PostgreSQL:
# CREATE DATABASE cryptosense;
