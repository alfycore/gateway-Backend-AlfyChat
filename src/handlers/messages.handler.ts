// ==========================================
// ALFYCHAT - MESSAGES HANDLER
// Gestion des événements de messages
// ==========================================

import { Server } from 'socket.io';
import { AuthenticatedSocket, Message } from '../types';
import { ServiceProxy } from '../services/proxy';
import { emitToSocket, emitError } from '../utils/emit';

export function registerMessageHandlers(
  socket: AuthenticatedSocket,
  io: Server,
  serviceProxy: ServiceProxy
): void {
  const userId = socket.userId!;

  // Créer un message
  socket.on('MESSAGE_CREATE', async (data) => {
    try {
      const message = await serviceProxy.messages.createMessage({
        ...data,
        senderId: userId,
      });
      
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_CREATE', {
        type: 'MESSAGE_CREATE',
        payload: message,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_CREATE_ERROR', error);
    }
  });

  // Mettre à jour un message
  socket.on('MESSAGE_UPDATE', async (data) => {
    try {
      const message = await serviceProxy.messages.updateMessage(data.messageId, data.content, userId);
      
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_UPDATE', {
        type: 'MESSAGE_UPDATE',
        payload: message,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_UPDATE_ERROR', error);
    }
  });

  // Supprimer un message
  socket.on('MESSAGE_DELETE', async (data) => {
    try {
      await serviceProxy.messages.deleteMessage(data.messageId, userId);
      
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_DELETE', {
        type: 'MESSAGE_DELETE',
        payload: { messageId: data.messageId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_DELETE_ERROR', error);
    }
  });

  // Ajouter une réaction
  socket.on('REACTION_ADD', async (data) => {
    try {
      await serviceProxy.messages.addReaction(data.messageId, userId, data.emoji);
      
      io.to(`conversation:${data.conversationId}`).emit('REACTION_ADD', {
        type: 'REACTION_ADD',
        payload: { messageId: data.messageId, userId, emoji: data.emoji },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  // Retirer une réaction
  socket.on('REACTION_REMOVE', async (data) => {
    try {
      await serviceProxy.messages.removeReaction(data.messageId, userId, data.emoji);
      
      io.to(`conversation:${data.conversationId}`).emit('REACTION_REMOVE', {
        type: 'REACTION_REMOVE',
        payload: { messageId: data.messageId, userId, emoji: data.emoji },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });
}
