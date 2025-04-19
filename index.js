import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

app.post('/signup', async (req, res) => {
  const { email, password, full_name, role } = req.body;

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .single();

  if (existingUser) {
    return res.status(409).json({ error: 'User already exists with this email' });
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  const { data, error } = await supabase.from('users').insert([
    {
      email,
      full_name,
      password: hashedPassword,
      role
    }
  ]);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.status(200).json({ message: 'Signup successful' });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
  
    const { data: user, error: fetchError } = await supabase
      .from('users')
      .select('id, email, full_name, password, role')
      .eq('email', email)
      .single();
  
    if (fetchError) {
      return res.status(500).json({ error: fetchError.message });
    }
  
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
  
    const isMatch = await bcrypt.compare(password, user.password);
  
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
  
    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
  
    const { password: _, ...safeUser } = user;
  
    res.status(200).json({
      message: 'Login successful',
      token,
      user: safeUser
    });
  });
  

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
