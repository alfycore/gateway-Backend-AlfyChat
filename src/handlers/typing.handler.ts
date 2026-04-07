// ==========================================
// ALFYCHAT - TYPING HANDLER
// Gestion des indicateurs de frappe
// ==========================================

import { Server } from 'socket.io';
import { AuthenticatedSocket } from '../types';
import { RedisClient } from '../utils/redis';

export function registerTypingHandlers(
  socket: AuthenticatedSocket,
  io: Server,
  redis: RedisClient
): void {
  const userId = socket.userId!;

  // Début de frappe
  socket.on('TYPING_START', async (data) => {
    await redis.setTyping(data.conversationId, userId);
    
    socket.to(`conversation:${data.conversationId}`).emit('TYPING_START', {
      type: 'TYPING_START',
      payload: { userId, conversationId: data.conversationId },
      timestamp: new Date(),
    });
  });

  // Fin de frappe
  socket.on('TYPING_STOP', async (data) => {
    await redis.removeTyping(data.conversationId, userId);
    
    socket.to(`conversation:${data.conversationId}`).emit('TYPING_STOP', {
      type: 'TYPING_STOP',
      payload: { userId, conversationId: data.conversationId },
      timestamp: new Date(),
    });
  });
}
