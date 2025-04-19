import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
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

// 👤 Sign Up Route
app.post('/signup', async (req, res) => {
  const { email, password, full_name, role } = req.body;

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const { data: authData, error: authError } = await supabase.auth.signUp({
    email,
    password
  });

  if (authError) {
    return res.status(400).json({ error: authError.message });
  }

  const userId = authData.user?.id;

  const { error: insertError } = await supabase.from('users').insert([
    {
      id: userId,
      email,
      full_name,
      role
    }
  ]);

  if (insertError) {
    return res.status(500).json({ error: insertError.message });
  }

  res.status(200).json({ message: 'Signup successful! Please verify your email.', user: authData.user });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const { data: sessionData, error: loginError } = await supabase.auth.signInWithPassword({
    email,
    password
  });

  if (loginError) {
    return res.status(401).json({ error: loginError.message });
  }

  res.status(200).json({
    message: 'Login successful',
    session: sessionData.session,
    user: sessionData.user
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));