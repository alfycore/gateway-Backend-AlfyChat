// ==========================================
// ALFYCHAT - WEBRTC HANDLER
// Signaling WebRTC pour les appels P2P
// ==========================================

import { Server } from 'socket.io';
import { AuthenticatedSocket } from '../types';

export function registerWebRTCHandlers(
  socket: AuthenticatedSocket,
  io: Server
): void {
  const userId = socket.userId!;

  // Offre WebRTC
  socket.on('WEBRTC_OFFER', (data) => {
    const payload = { type: 'WEBRTC_OFFER', payload: { ...data, fromUserId: userId }, timestamp: new Date() };
    if (data.targetUserId) {
      // Appel de groupe : router vers un pair spécifique
      io.to(`user:${data.targetUserId}`).emit('WEBRTC_OFFER', payload);
    } else {
      socket.to(`call:${data.callId}`).emit('WEBRTC_OFFER', payload);
    }
  });

  // Réponse WebRTC
  socket.on('WEBRTC_ANSWER', (data) => {
    const payload = { type: 'WEBRTC_ANSWER', payload: { ...data, fromUserId: userId }, timestamp: new Date() };
    if (data.targetUserId) {
      io.to(`user:${data.targetUserId}`).emit('WEBRTC_ANSWER', payload);
    } else {
      socket.to(`call:${data.callId}`).emit('WEBRTC_ANSWER', payload);
    }
  });

  // Candidat ICE
  socket.on('WEBRTC_ICE_CANDIDATE', (data) => {
    const payload = { type: 'WEBRTC_ICE_CANDIDATE', payload: { ...data, fromUserId: userId }, timestamp: new Date() };
    if (data.targetUserId) {
      io.to(`user:${data.targetUserId}`).emit('WEBRTC_ICE_CANDIDATE', payload);
    } else {
      socket.to(`call:${data.callId}`).emit('WEBRTC_ICE_CANDIDATE', payload);
    }
  });

  // Négociation nécessaire
  socket.on('WEBRTC_NEGOTIATION_NEEDED', (data) => {
    socket.to(`call:${data.callId}`).emit('WEBRTC_NEGOTIATION_NEEDED', {
      type: 'WEBRTC_NEGOTIATION_NEEDED',
      payload: { ...data, fromUserId: userId },
      timestamp: new Date(),
    });
  });

  // Statistiques de connexion
  socket.on('WEBRTC_STATS', (data) => {
    // Log les statistiques pour monitoring
    console.log(`WebRTC Stats - User: ${userId}, Call: ${data.callId}`, data.stats);
  });
}
