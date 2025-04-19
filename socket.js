import { WebSocketServer } from 'ws';
import { config } from 'dotenv';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

config()
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// Track connected users per course
const clientsByCourse = {};

export const setupWebSocket = (server) => {
  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws, req) => {
    const params = new URLSearchParams(req.url.split('?')[1]);
    const token = params.get('token');
    const courseId = params.get('courseId');

    if (!token || !courseId) return ws.close();

    // Verify token
    let user;
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      console.error('JWT verification failed');
      return ws.close();
    }

    const socketInfo = { ws, userId: user.id, courseId };

    // Add socket to course group
    if (!clientsByCourse[courseId]) clientsByCourse[courseId] = [];
    clientsByCourse[courseId].push(socketInfo);

    console.log(`User ${user.id} joined course ${courseId}`);

    // Handle incoming message
    ws.on('message', async (msg) => {
      const parsed = JSON.parse(msg);

      if (!parsed.content) return;

      // Save message in DB
      const { data, error } = await supabase.from('messages').insert([
        {
          course_id: courseId,
          sender_id: user.id,
          content: parsed.content,
        },
      ]);

      if (error) return console.error('DB error:', error.message);

      // Broadcast to all in course
      const broadcast = JSON.stringify({
        type: 'message',
        content: parsed.content,
        sender_id: user.id,
        course_id: courseId,
        created_at: new Date().toISOString(),
      });

      clientsByCourse[courseId].forEach(client => {
        if (client.ws.readyState === ws.OPEN) {
          client.ws.send(broadcast);
        }
      });
    });

    ws.on('close', () => {
      clientsByCourse[courseId] = clientsByCourse[courseId].filter(c => c.ws !== ws);
      console.log(`User ${user.id} left course ${courseId}`);
    });
  });

  console.log('✅ WebSocket server running');
};
