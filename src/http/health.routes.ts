import type { Express } from 'express';
import jwt from 'jsonwebtoken';
import { runtime } from '../state/runtime';
import { connectedClients } from '../state/connections';
import { JWT_SECRET } from '../config/env';

export function registerHealthRoutes(app: Express): void {
  // Health check
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'gateway',
      uptime: process.uptime(),
      connections: connectedClients.size,
      timestamp: new Date(),
    });
  });

  app.get('/stats', (req, res) => {
    res.json({
      connections: connectedClients.size,
      rooms: runtime.io.sockets.adapter.rooms.size,
    });
  });

  // Mobile socket diagnostic endpoint
  app.get('/api/socket/status', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '');
    let tokenValid = false;
    let userId: string | null = null;

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
        tokenValid = true;
        userId = decoded.userId;
      } catch {}
    }

    res.json({
      status: 'ok',
      socketIO: true,
      transports: ['websocket', 'polling'],
      tokenProvided: !!token,
      tokenValid,
      userId,
      timestamp: new Date(),
    });
  });
}
