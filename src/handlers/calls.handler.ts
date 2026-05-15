// ==========================================
// ALFYCHAT - CALLS HANDLER (référence, non utilisé — les handlers sont dans index.ts)
// Appels DM et groupe via WebRTC P2P mesh (pas de LiveKit)
// ==========================================

import { Server } from 'socket.io';
import { AuthenticatedSocket } from '../types';
import { ServiceProxy } from '../services/proxy';
import { emitError } from '../utils/emit';

export function registerCallsHandlers(
  socket: AuthenticatedSocket,
  io: Server,
  serviceProxy: ServiceProxy
): void {
  const userId = socket.userId!;
  const user   = (socket as any).user as { displayName?: string; username?: string; avatarUrl?: string } | undefined;
  const userName = user?.displayName || user?.username || userId;

  // Initier un appel DM ou groupe
  socket.on('CALL_INITIATE', async (data, callback) => {
    try {
      let callId: string;
      if (data.channelId) {
        const groupCall = await serviceProxy.calls.createGroupCall({
          channelId: data.channelId,
          initiatorId: userId,
          type: data.type || 'voice',
        }) as { id?: string; callId?: string };
        callId = groupCall.id || groupCall.callId || '';
        socket.join(`call:${callId}`);
        socket.to(`channel:${data.channelId}`).emit('CALL_INCOMING', {
          type: 'CALL_INCOMING',
          payload: { callId, channelId: data.channelId, isGroup: true, initiatorId: userId, callerName: userName, callType: data.type || 'voice' },
          timestamp: new Date(),
        });
      } else {
        const call = await serviceProxy.calls.initiateCall({ type: data.type, initiatorId: userId, conversationId: data.conversationId, recipientId: data.recipientId }) as { id?: string; callId?: string };
        callId = call.id || call.callId || '';
        socket.join(`call:${callId}`);
        if (data.recipientId) {
          io.to(`user:${data.recipientId}`).emit('CALL_INCOMING', {
            type: 'CALL_INCOMING',
            payload: { callId, recipientId: data.recipientId, isGroup: false, initiatorId: userId, callerName: userName, callType: data.type || 'voice' },
            timestamp: new Date(),
          });
        }
      }
      if (typeof callback === 'function') callback({ callId, id: callId });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Failed to initiate call' });
    }
  });

  // Rejoindre un appel groupe
  socket.on('CALL_JOIN', async (data, callback) => {
    try {
      const socketsInRoom = await io.in(`call:${data.callId}`).fetchSockets();
      const existingParticipants = socketsInRoom.map((s) => (s as any).userId as string).filter(Boolean);
      await serviceProxy.calls.joinCall(data.callId, userId);
      socket.join(`call:${data.callId}`);
      socket.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_JOINED', {
        type: 'CALL_PARTICIPANT_JOINED',
        payload: { callId: data.callId, userId, userName, userAvatar: user?.avatarUrl, existingParticipants: [] },
        timestamp: new Date(),
      });
      if (typeof callback === 'function') callback({ callId: data.callId, existingParticipants });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  // Accepter un appel 1:1
  socket.on('CALL_ACCEPT', async (data) => {
    try {
      const socketsInRoom = await io.in(`call:${data.callId}`).fetchSockets();
      const existingParticipants = socketsInRoom.map((s) => (s as any).userId as string).filter((uid) => uid !== userId);
      await serviceProxy.calls.joinCall(data.callId, userId);
      socket.join(`call:${data.callId}`);
      socket.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_JOINED', {
        type: 'CALL_PARTICIPANT_JOINED',
        payload: { callId: data.callId, userId, userName, userAvatar: user?.avatarUrl, existingParticipants: [] },
        timestamp: new Date(),
      });
      io.to(`call:${data.callId}`).emit('CALL_ACCEPT', {
        type: 'CALL_ACCEPT',
        payload: { callId: data.callId, userId, existingParticipants },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  socket.on('CALL_REJECT', async (data) => {
    try {
      await serviceProxy.calls.rejectCall(data.callId, userId);
      io.to(`call:${data.callId}`).emit('CALL_REJECT', { type: 'CALL_REJECT', payload: { callId: data.callId, userId }, timestamp: new Date() });
    } catch (error) { emitError(socket, 'CALL_ERROR', error); }
  });

  socket.on('CALL_LEAVE', async (data) => {
    try {
      await serviceProxy.calls.leaveCall(data.callId, userId);
      socket.leave(`call:${data.callId}`);
      io.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_LEFT', { type: 'CALL_PARTICIPANT_LEFT', payload: { callId: data.callId, userId }, timestamp: new Date() });
      const remaining = await io.in(`call:${data.callId}`).fetchSockets();
      if (remaining.length === 0) {
        await serviceProxy.calls.endCall(data.callId, userId);
        io.to(`call:${data.callId}`).emit('CALL_END', { type: 'CALL_END', payload: { callId: data.callId }, timestamp: new Date() });
      }
    } catch (error) { emitError(socket, 'CALL_ERROR', error); }
  });

  socket.on('CALL_END', async (data) => {
    try {
      await serviceProxy.calls.endCall(data.callId, userId);
      io.to(`call:${data.callId}`).emit('CALL_END', { type: 'CALL_END', payload: { callId: data.callId }, timestamp: new Date() });
      io.socketsLeave(`call:${data.callId}`);
    } catch (error) { emitError(socket, 'CALL_ERROR', error); }
  });

  socket.on('CALL_SCREEN_SHARE', (data) => {
    socket.to(`call:${data.callId}`).emit('CALL_SCREEN_SHARE', {
      type: 'CALL_SCREEN_SHARE',
      payload: { callId: data.callId, userId, active: data.active },
      timestamp: new Date(),
    });
  });
}
