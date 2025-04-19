import express from 'express'
import cors from 'cors'
import { config } from 'dotenv';

import { createClient } from '@supabase/supabase-js';

config();

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }))

const PORT = process.env.PORT || 3000;
console.log(supabase)

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));