// traditiona auth done (no problem)
import express from 'express';
import bcrypt from 'bcryptjs';
import userModel from '../models/user.model.js';
import { verifyRecaptcha } from '../middlewares/verifyRecaptcha.js';

const traditionalAuth = express.Router();

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      // console.log('Login attempt failed: Missing email or password');
      return res.status(400).json({
        success: false,
        message: "Both email and password are required!"
      });
    }

    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
      // console.log(`Login attempt failed: User with email ${email} not found`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials!"
      });
    }

    const isMatchedPassword = await bcrypt.compare(password, user.password);
    if (!isMatchedPassword) {
      // console.log(`Login attempt failed: Incorrect password for user ${email}`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials!"
      });
    }

    // Store user in session
    req.session.user = {
      _id: user._id,
      email: user.email,
      name: user.name
    };

    // Save the session
    req.session.save(err => {
      if (err) {
        // console.error('Session save error:', err);
        return res.status(500).json({
          success: false,
          message: "Session error occurred"
        });
      }

      // console.log('\n=== Successful Login ===');
      // console.log(`User: ${user.email}`);
      // console.log('Session created with ID:', req.sessionID);

      user.password = undefined;

      return res.status(200).json({
        success: true,
        message: "Login successful!",
        user
      });
    });

  } catch (error) {
    // console.error('\n=== Login Error ===\n', error);
    return res.status(500).json({
      success: false,
      message: "An unexpected error occurred during login."
    });
  }
};

export const signup = async (req, res) => {
  try {
    console.log("Signup route is triggered!");

    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      // console.log('Signup attempt failed: Missing fields');
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required!"
      });
    }

    const isDuplicate = await userModel.findOne({ email });
    if (isDuplicate) {
      // console.log(`Signup attempt failed: Email ${email} already exists`);
      return res.status(409).json({
        success: false,
        message: "Email already exists!"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await userModel.create({
      name,
      email,
      password: hashedPassword
    });

    // Store user in session
    req.session.user = {
      _id: user._id,
      email: user.email,
      name: user.name
    };

    // Save the session
    req.session.save(err => {
      if (err) {
        // console.error('Session save error:', err);
        return res.status(500).json({
          success: false,
          message: "Session error occurred"
        });
      }

      user.password = undefined;

      // console.log('\n=== Successful Signup ===');
      // console.log(`New user: ${user.email}`);

      return res.status(201).json({
        success: true,
        message: "User registered successfully!",
        user
      });
    });

  } catch (error) {
    // console.error('\n=== Signup Error ===\n', error);
    return res.status(500).json({
      success: false,
      message: "An unexpected error occurred during registration."
    });
  }
};

// session verification endpoint
export const verifySession = (req, res) => {
  if (req.session.user) {
    return res.status(200).json({
      success: true,
      user: req.session.user
    });
  }
  res.status(401).json({
    success: false,
    message: "Not authenticated"
  });
};


traditionalAuth.post('/login', verifyRecaptcha, login); // endpoint -> '/auth/login'
traditionalAuth.post('/signup', verifyRecaptcha, signup); // endpoint -> '/auth/signup'
traditionalAuth.get('/verify-session', verifySession);

export default traditionalAuth;