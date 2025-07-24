import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

// Load environment variables
dotenv.config();

// Validate essential environment variables
const requiredEnvVars = ['PORT', 'MONGO_URI', 'JWT_SECRET'];
requiredEnvVars.forEach((envVar) => {
  if (!process.env[envVar]) throw new Error(`❌ Missing ${envVar} in .env`);
});

const app = express();

// ======================
// Middleware
// ======================
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:8080',  // ✅ Updated here
  credentials: true
}));
app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));
app.use(express.json({ limit: '10kb' }));

// ======================
// Routes
// ======================
import authRoutes from './routes/authRoutes.js';

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'UP', timestamp: new Date() });
});

app.post('/api/test', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  res.json({ success: true });
});

app.use('/api/auth', authRoutes);

// ======================
// Root route for Render
// ======================
app.get("/", (req, res) => {
  res.send("🚀 MovieWorld Backend is running!");
});

// ======================
// Database & Server
// ======================
const PORT = process.env.PORT || 5000;

let MONGO_URI = process.env.MONGO_URI;
if (MONGO_URI.includes('<PASSWORD>')) {
  MONGO_URI = MONGO_URI.replace(
    '<PASSWORD>',
    encodeURIComponent(process.env.MONGO_PASSWORD || '')
  );
}

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ======================
// Graceful Shutdown
// ======================
process.on('SIGTERM', () => {
  mongoose.connection.close(() => {
    console.log('🔌 MongoDB connection closed');
    process.exit(0);
  });
});

// 404 Not Found Handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});
