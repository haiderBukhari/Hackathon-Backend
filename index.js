import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import bcrypt from 'bcrypt';
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

app.post('/signup', async (req, res) => {
  const { email, password, full_name, role } = req.body;

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if user already exists
  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .single();

  if (existingUser) {
    return res.status(409).json({ error: 'User already exists with this email' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  // Insert user
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

  // Fetch user by email
  const { data: user, error } = await supabase
    .from('users')
    .select('id, email, full_name, password, role')
    .eq('email', email)
    .single();

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Compare passwords
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Remove password before sending response
  const { password: _, ...safeUser } = user;

  res.status(200).json({
    message: 'Login successful',
    user: safeUser
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
