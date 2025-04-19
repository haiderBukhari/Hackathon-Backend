import { config } from 'dotenv';
import http from 'http';
import { setupWebSocket } from './socket.js'; // 👈 This contains the WebSocket logic
import app from './app.js';

config();


const server = http.createServer(app);

setupWebSocket(server);

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`HTTP + WebSocket server running on port ${PORT}`);
});
