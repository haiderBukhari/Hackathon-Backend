import { configDotenv } from 'dotenv';
import jwt from 'jsonwebtoken';
configDotenv();

const JWT_SECRET = process.env.JWT_SECRET;

export function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1]; // Format: "Bearer <token>"

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Contains id and role
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}
