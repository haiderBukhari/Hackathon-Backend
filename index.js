import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { verifyToken } from './middleware/verifyUser.js';
import multer from 'multer';
import axios from 'axios';
import FormData from 'form-data';

config();

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const upload = multer({ dest: "uploads/" });

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

app.post('/courses', verifyToken, async (req, res) => {
    const { title, description, thumbnail_url } = req.body;

    if (req.user.role !== 'tutor') {
        return res.status(403).json({ error: 'Only tutors can create courses' });
    }

    const { data, error } = await supabase
        .from('courses')
        .insert([
            {
                title,
                description,
                thumbnail_url,
                tutor_id: req.user.id
            }
        ])
        .select(); // This tells Supabase to return the inserted row(s)

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(201).json({ message: 'Course created', course: data[0] });
});

app.get('/courses', verifyToken, async (req, res) => {
    if (req.user.role !== 'tutor') {
        return res.status(403).json({ error: 'Only tutors can view their courses' });
    }

    const { data, error } = await supabase
        .from('courses')
        .select('*')
        .eq('tutor_id', req.user.id);

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json(data);
});

app.get('/courses/:id', verifyToken, async (req, res) => {
    const { id } = req.params;

    const { data, error } = await supabase
        .from('courses')
        .select('*')
        .eq('id', id)
        .single();

    if (error || !data) {
        return res.status(404).json({ error: 'Course not found' });
    }

    res.status(200).json(data);
});

app.put('/courses/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, thumbnail_url } = req.body;

    const { data: existing, error: fetchError } = await supabase
        .from('courses')
        .select('*')
        .eq('id', id)
        .single();

    if (fetchError || !existing) {
        return res.status(404).json({ error: 'Course not found' });
    }

    if (existing.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You are not the owner of this course' });
    }

    const { data, error } = await supabase
        .from('courses')
        .update({
            title,
            description,
            thumbnail_url
        })
        .eq('id', id)
        .select();

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ message: 'Course updated', course: data[0] });
});

app.delete('/courses/:id', verifyToken, async (req, res) => {
    const { id } = req.params;

    const { data: existing, error: fetchError } = await supabase
        .from('courses')
        .select('*')
        .eq('id', id)
        .single();

    if (fetchError || !existing) {
        return res.status(404).json({ error: 'Course not found' });
    }

    if (existing.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You are not the owner of this course' });
    }

    const { error } = await supabase
        .from('courses')
        .delete()
        .eq('id', id);

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ message: 'Course deleted successfully' });
});

app.post('/courses/:courseId/videos', verifyToken, async (req, res) => {
    const { courseId } = req.params;
    const { title, video_url, order_index } = req.body;

    // Verify ownership of the course
    const { data: course, error: fetchError } = await supabase
        .from('courses')
        .select('tutor_id')
        .eq('id', courseId)
        .single();

    if (fetchError || !course) {
        return res.status(404).json({ error: 'Course not found' });
    }

    if (course.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You do not own this course' });
    }

    const { data, error } = await supabase
        .from('videos')
        .insert([
            {
                title,
                video_url,
                order_index,
                course_id: courseId
            }
        ])
        .select();

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(201).json({ message: 'Video added successfully', video: data[0] });
});

app.get('/courses/:courseId/videos', verifyToken, async (req, res) => {
    const { courseId } = req.params;

    const { data, error } = await supabase
        .from('videos')
        .select('*')
        .eq('course_id', courseId)
        .order('order_index', { ascending: true });

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ videos: data });
});

app.delete('/courses/:courseId/videos/:videoId', verifyToken, async (req, res) => {
    const { courseId, videoId } = req.params;

    // Verify ownership of the course
    const { data: course, error: fetchError } = await supabase
        .from('courses')
        .select('tutor_id')
        .eq('id', courseId)
        .single();

    if (fetchError || !course) {
        return res.status(404).json({ error: 'Course not found' });
    }

    if (course.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You do not own this course' });
    }

    const { error: deleteError } = await supabase
        .from('videos')
        .delete()
        .eq('id', videoId)
        .eq('course_id', courseId);

    if (deleteError) {
        return res.status(500).json({ error: deleteError.message });
    }

    res.status(200).json({ message: 'Video deleted successfully' });
});

app.put('/courses/:courseId/videos/:videoId', verifyToken, async (req, res) => {
    const { courseId, videoId } = req.params;
    const { title, video_url, order_index } = req.body;

    // Step 1: Verify that the course exists and belongs to this tutor
    const { data: course, error: courseError } = await supabase
        .from('courses')
        .select('tutor_id')
        .eq('id', courseId)
        .single();

    if (courseError || !course) {
        return res.status(404).json({ error: 'Course not found' });
    }

    if (course.tutor_id !== req.user.id) {
        return res.status(403).json({ error: 'You do not own this course' });
    }

    // Step 2: Verify the video belongs to the course
    const { data: video, error: videoError } = await supabase
        .from('videos')
        .select('id')
        .eq('id', videoId)
        .eq('course_id', courseId)
        .single();

    if (videoError || !video) {
        return res.status(404).json({ error: 'Video not found for this course' });
    }

    // Step 3: Update video
    const { data: updatedVideo, error: updateError } = await supabase
        .from('videos')
        .update({
            title,
            video_url,
            order_index
        })
        .eq('id', videoId)
        .select();

    if (updateError) {
        return res.status(500).json({ error: updateError.message });
    }

    res.status(200).json({ message: 'Video updated successfully', video: updatedVideo[0] });
});

app.post('/transcribe/:videoId', upload.single('video'), async (req, res) => {
    const { videoId } = req.params;

    if (!videoId) {
        return res.status(400).json({ error: 'videoId is required in URL' });
    }

    try {
        const filePath = req.file.path;

        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));
        formData.append('model', 'whisper-1');
        formData.append('response_format', 'text');

        const response = await axios.post('https://api.openai.com/v1/audio/transcriptions', formData, {
            headers: {
                Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
                ...formData.getHeaders(),
            },
        });

        const transcriptText = response.data;

        // Insert into Supabase transcripts table
        const { data, error } = await supabase.from('transcripts').insert([
            {
                video_id: videoId,
                content: transcriptText,
            },
        ]);

        fs.unlinkSync(filePath); // Clean up the file

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        res.status(200).json({
            message: 'Transcription completed and saved',
            transcript: transcriptText,
            saved: data[0],
        });
    } catch (error) {
        console.error('Error transcribing:', error.response?.data || error.message);
        res.status(500).send('Transcription failed');
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
