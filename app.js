import express from 'express'
import cors from 'cors';
import { config } from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { verifyToken } from './middleware/verifyUser.js';

const app = express();

app.use(express.json());
app.use(cors({ origin: '*' }));

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);
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
    const { title, video_url, order_index, transcript } = req.body;

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
                transcript,
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

app.get('/courses/:courseId/videos/:videoId', verifyToken, async (req, res) => {
    const { courseId, videoId } = req.params;

    try {
        // Optional: You can verify tutor ownership here like in other routes if needed

        const { data: video, error } = await supabase
            .from('videos')
            .select('*')
            .eq('id', videoId)
            .eq('course_id', courseId)
            .single();

        if (error || !video) {
            return res.status(404).json({ error: 'Video not found for this course' });
        }

        res.status(200).json(video);
    } catch (err) {
        console.error('Error fetching video:', err.message);
        res.status(500).json({ error: 'Failed to retrieve video' });
    }
});

app.get('/student/courses', verifyToken, async (req, res) => {
    const studentId = req.user.id;

    if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Only students can view this list' });
    }

    try {
        const { data, error } = await supabase
            .from('courses')
            .select(`
          *,
          enrollments!left(course_id,student_id,id)
        `)
            .order('created_at', { ascending: false });

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        // Enrich each course with isEnrolled = true/false
        const result = data.map(course => ({
            ...course,
            isEnrolled: course.enrollments?.some(e => e.student_id === studentId) || false,
        }));

        res.status(200).json(result);
    } catch (err) {
        console.error('Error fetching student courses:', err.message);
        res.status(500).json({ error: 'Failed to fetch courses' });
    }
});

app.post('/student/enroll/:courseId', verifyToken, async (req, res) => {
    const { courseId } = req.params;
    const studentId = req.user.id;

    if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Only students can enroll' });
    }

    // Check if already enrolled
    const { data: existingEnrollment } = await supabase
        .from('enrollments')
        .select('id')
        .eq('student_id', studentId)
        .eq('course_id', courseId)
        .single();

    if (existingEnrollment) {
        return res.status(409).json({ message: 'Already enrolled in this course' });
    }

    // Enroll student
    const { data, error } = await supabase
        .from('enrollments')
        .insert([
            {
                student_id: studentId,
                course_id: courseId,
            },
        ])
        .select();

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(201).json({ message: 'Enrolled successfully', enrollment: data[0] });
});
app.delete('/student/unenroll/:courseId', verifyToken, async (req, res) => {
    const { courseId } = req.params;
    const studentId = req.user.id;

    if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Only students can unenroll' });
    }

    // Delete the enrollment
    const { error } = await supabase
        .from('enrollments')
        .delete()
        .eq('student_id', studentId)
        .eq('course_id', courseId);

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ message: 'Unenrolled successfully' });
});

app.get('/courses/:courseId/students', verifyToken, async (req, res) => {
    const { courseId } = req.params;

    try {
        const { data, error } = await supabase
            .from('enrollments')
            .select('id, student_id, enrolled_at, users(id, full_name, email)')
            .eq('course_id', courseId);

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        const students = data.map(enrollment => ({
            student_id: enrollment.student_id,
            full_name: enrollment.users?.full_name || 'Unknown',
            email: enrollment.users?.email || '',
            enrolled_at: enrollment.enrolled_at,
        }));

        res.status(200).json({ students });
    } catch (err) {
        console.error('Error fetching enrolled students:', err.message);
        res.status(500).json({ error: 'Failed to fetch enrolled students' });
    }
});

app.get('/tutor/enrollment-stats', verifyToken, async (req, res) => {
    const tutorId = req.user.id;

    try {
        // Step 1: Get tutor's courses
        const { data: courses, error: courseError } = await supabase
            .from('courses')
            .select('id, title')
            .eq('tutor_id', tutorId);

        if (courseError) {
            return res.status(500).json({ error: courseError.message });
        }

        const courseIds = courses.map(course => course.id);
        if (courseIds.length === 0) {
            return res.status(200).json({
                total_students_enrolled: 0,
                recent_enrollments: [],
            });
        }

        // Step 2: Get total enrollment count
        const { count: totalCount, error: totalCountError } = await supabase
            .from('enrollments')
            .select('*', { count: 'exact', head: true })
            .in('course_id', courseIds);

        if (totalCountError) {
            return res.status(500).json({ error: totalCountError.message });
        }

        // Step 3: Get enrollments in last 7 days
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

        const { data: recentEnrollments, error: recentError } = await supabase
            .from('enrollments')
            .select('id, course_id, enrolled_at')
            .in('course_id', courseIds)
            .gte('enrolled_at', sevenDaysAgo);

        if (recentError) {
            return res.status(500).json({ error: recentError.message });
        }

        // Step 4: Map recent enrollments per course
        const enrollmentMap = {};
        courses.forEach(course => {
            enrollmentMap[course.id] = {
                course_id: course.id,
                title: course.title,
                recent_enrollments: 0,
            };
        });

        recentEnrollments.forEach(enrollment => {
            if (enrollmentMap[enrollment.course_id]) {
                enrollmentMap[enrollment.course_id].recent_enrollments += 1;
            }
        });

        const recent_enrollments = Object.values(enrollmentMap);

        // ✅ Final response
        res.status(200).json({
            total_students_enrolled: totalCount,
            recent_enrollments,
        });
    } catch (err) {
        console.error('Error fetching tutor enrollment stats:', err.message);
        res.status(500).json({ error: 'Failed to fetch enrollment stats' });
    }
});

export default app;