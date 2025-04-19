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

    // 👤 Fetch full_name from users table
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('full_name')
      .eq('id', user.id)
      .single();

    const senderName = userData?.full_name || 'Unknown';

    // 🧠 Track users by course and video
    if (!clientsByRoom[courseId]) clientsByRoom[courseId] = {};
    if (!clientsByRoom[courseId][videoId]) clientsByRoom[courseId][videoId] = [];

    const socketInfo = { ws, userId: user.id };
    clientsByRoom[courseId][videoId].push(socketInfo);

    console.log(`✅ ${senderName} joined course ${courseId}, video ${videoId}`);

    // 📜 Load and send chat history
    const { data: history, error: historyError } = await supabase
      .from('messages')
      .select('id, course_id, video_id, sender_id, content, created_at, users(full_name)')
      .eq('course_id', courseId)
      .eq('video_id', videoId)
      .order('created_at', { ascending: true });

    if (!historyError && history.length) {
      const messagesWithNames = history.map(msg => ({
        id: msg.id,
        course_id: msg.course_id,
        video_id: msg.video_id,
        sender_id: msg.sender_id,
        content: msg.content,
        created_at: msg.created_at,
        sender_name: msg.users?.full_name || 'Unknown',
      }));

      ws.send(JSON.stringify({ type: 'history', messages: messagesWithNames }));
    }

    // 📤 Handle incoming messages
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
        sender_name: senderName, // 🧑 Include full name
        created_at: new Date().toISOString(),
      };

      clientsByRoom[courseId][videoId].forEach(client => {
        if (client.ws.readyState === ws.OPEN) {
          client.ws.send(JSON.stringify(messagePayload));
        }
      });
    });

    // 🧹 Clean up on disconnect
    ws.on('close', () => {
      clientsByRoom[courseId][videoId] = clientsByRoom[courseId][videoId].filter(c => c.ws !== ws);
      console.log(`👋 ${senderName} left course ${courseId}, video ${videoId}`);
    });
  });

  console.log('✅ WebSocket server running with user names + chat history');
};
