import { WebSocketServer } from 'ws';
import { config } from 'dotenv';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// { courseId: { videoId: [ { ws, userId } ] } }
const clientsByRoom = {};

export const setupWebSocket = (server) => {
  const wss = new WebSocketServer({ server });

  wss.on('connection', async (ws, req) => {
    const params = new URLSearchParams(req.url.split('?')[1]);
    const token = params.get('token');
    const courseId = params.get('courseId');
    const videoId = params.get('videoId');

    if (!token || !courseId || !videoId) return ws.close();

    // 🔐 Verify JWT
    let user;
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      console.error('JWT verification failed');
      return ws.close();
    }

    // 🧠 Track users by course and video
    if (!clientsByRoom[courseId]) clientsByRoom[courseId] = {};
    if (!clientsByRoom[courseId][videoId]) clientsByRoom[courseId][videoId] = [];

    const socketInfo = { ws, userId: user.id };
    clientsByRoom[courseId][videoId].push(socketInfo);

    console.log(`User ${user.id} joined course ${courseId}, video ${videoId}`);

    // 📥 Send message history for the video
    const { data: history, error: historyError } = await supabase
      .from('messages')
      .select('*')
      .eq('course_id', courseId)
      .eq('video_id', videoId)
      .order('created_at', { ascending: true });

    if (!historyError && history.length) {
      ws.send(JSON.stringify({ type: 'history', messages: history }));
    }

    // 📤 Handle incoming message
    ws.on('message', async (msg) => {
      const parsed = JSON.parse(msg);
      if (!parsed.content) return;

      const { data, error } = await supabase.from('messages').insert([
        {
          course_id: courseId,
          video_id: videoId,
          sender_id: user.id,
          content: parsed.content,
        },
      ]);

      if (error) {
        console.error('DB insert error:', error.message);
        return;
      }

      const messagePayload = {
        type: 'message',
        content: parsed.content,
        course_id: courseId,
        video_id: videoId,
        sender_id: user.id,
        created_at: new Date().toISOString(),
      };

      // 🔁 Broadcast to all users in the same course+video room
      clientsByRoom[courseId][videoId].forEach(client => {
        if (client.ws.readyState === ws.OPEN) {
          client.ws.send(JSON.stringify(messagePayload));
        }
      });
    });

    // 🛑 Clean up on close
    ws.on('close', () => {
      clientsByRoom[courseId][videoId] = clientsByRoom[courseId][videoId].filter(c => c.ws !== ws);
      console.log(`User ${user.id} left course ${courseId}, video ${videoId}`);
    });
  });

  console.log('✅ WebSocket server with course + video chat support is running');
};