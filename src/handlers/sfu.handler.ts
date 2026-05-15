// ==========================================
// ALFYCHAT - SFU HANDLER (mediasoup relay)
// Relay des events Socket.IO vers le media-server
// pour les appels groupe (>10 participants) et serveur (≤1500).
// ==========================================

import { Server } from 'socket.io';
import type { AuthenticatedSocket } from '../types';
import type { ServiceProxy } from '../services/proxy';
import { emitError } from '../utils/emit';

// Redis key : call:mode:<callId> → 'p2p' | 'sfu'
export const GROUP_SFU_THRESHOLD = parseInt(process.env.GROUP_SFU_THRESHOLD || '10');

export function registerSfuHandlers(
  socket: AuthenticatedSocket,
  io: Server,
  serviceProxy: ServiceProxy,
): void {
  const userId = socket.userId!;

  // ── RTP Capabilities ────────────────────────────────────────────────────────
  // Client a besoin des codecs supportés par le router pour créer son Device mediasoup-client
  socket.on('SFU_GET_RTP_CAPABILITIES', async (data: { callId: string }, callback) => {
    try {
      const result = await serviceProxy.media.getRtpCapabilities(data.callId);
      if (typeof callback === 'function') callback(result);
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Impossible de récupérer les capabilities' });
    }
  });

  // ── Transport ───────────────────────────────────────────────────────────────
  socket.on('SFU_CREATE_TRANSPORT', async (
    data: { callId: string; direction: 'send' | 'recv' },
    callback,
  ) => {
    try {
      const result = await serviceProxy.media.createTransport(data.callId, userId, data.direction);
      if (typeof callback === 'function') callback(result);
      else socket.emit('SFU_TRANSPORT_CREATED', { ...result, callId: data.callId });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Erreur création transport' });
    }
  });

  socket.on('SFU_CONNECT_TRANSPORT', async (
    data: { callId: string; transportId: string; dtlsParameters: unknown },
    callback,
  ) => {
    try {
      await serviceProxy.media.connectTransport(data.callId, data.transportId, data.dtlsParameters);
      if (typeof callback === 'function') callback({ success: true });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Erreur connexion transport' });
    }
  });

  // ── Producers ───────────────────────────────────────────────────────────────
  socket.on('SFU_PRODUCE', async (
    data: { callId: string; transportId: string; kind: 'audio' | 'video'; rtpParameters: unknown; appData?: unknown },
    callback,
  ) => {
    try {
      const result = await serviceProxy.media.produce(
        data.callId, data.transportId, data.kind, data.rtpParameters, userId, data.appData,
      );

      if (typeof callback === 'function') callback(result);
      else socket.emit('SFU_PRODUCED', { ...result, callId: data.callId });

      // Notifier tous les autres participants de la salle qu'un nouveau producer est dispo
      socket.to(`call:${data.callId}`).emit('SFU_NEW_PRODUCER', {
        type: 'SFU_NEW_PRODUCER',
        payload: {
          callId: data.callId,
          producerId: result.producerId,
          userId,
          kind: data.kind,
        },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Erreur création producer' });
    }
  });

  socket.on('SFU_CLOSE_PRODUCER', async (
    data: { callId: string; producerId: string },
  ) => {
    try {
      await serviceProxy.media.closeProducer(data.callId, data.producerId);
      socket.to(`call:${data.callId}`).emit('SFU_PRODUCER_CLOSED', {
        type: 'SFU_PRODUCER_CLOSED',
        payload: { callId: data.callId, producerId: data.producerId, userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
    }
  });

  // ── Consumers ───────────────────────────────────────────────────────────────
  socket.on('SFU_CONSUME', async (
    data: { callId: string; producerId: string; rtpCapabilities: unknown; recvTransportId: string },
    callback,
  ) => {
    try {
      const result = await serviceProxy.media.consume(
        data.callId, data.recvTransportId, data.producerId, data.rtpCapabilities, userId,
      );
      if (typeof callback === 'function') callback(result);
      else socket.emit('SFU_CONSUMED', { ...result, callId: data.callId });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Erreur création consumer' });
    }
  });

  socket.on('SFU_RESUME_CONSUMER', async (
    data: { callId: string; consumerId: string },
    callback,
  ) => {
    try {
      await serviceProxy.media.resumeConsumer(data.callId, data.consumerId);
      if (typeof callback === 'function') callback({ success: true });
    } catch (error) {
      emitError(socket, 'SFU_ERROR', error);
    }
  });

  // ── Raise / Lower hand (appels serveur) ─────────────────────────────────────
  socket.on('CALL_RAISE_HAND', (data: { callId: string }) => {
    socket.to(`call:${data.callId}`).emit('CALL_HAND_RAISED', {
      type: 'CALL_HAND_RAISED',
      payload: { callId: data.callId, userId },
      timestamp: new Date(),
    });
  });

  socket.on('CALL_LOWER_HAND', (data: { callId: string }) => {
    socket.to(`call:${data.callId}`).emit('CALL_HAND_LOWERED', {
      type: 'CALL_HAND_LOWERED',
      payload: { callId: data.callId, userId },
      timestamp: new Date(),
    });
  });
}

// ── Broadcast d'un update de qualité depuis le media-server ─────────────────
// Appelé par l'endpoint HTTP /internal/call-quality dans index.ts
export function broadcastQualityUpdate(
  io: Server,
  callId: string,
  tier: number,
  participantCount: number,
  tierParams: unknown,
) {
  io.to(`call:${callId}`).emit('CALL_QUALITY_UPDATE', {
    type: 'CALL_QUALITY_UPDATE',
    payload: { callId, tier, participantCount, tierParams },
    timestamp: new Date(),
  });
}

// ── Broadcast d'un switch P2P→SFU ───────────────────────────────────────────
export function broadcastModeSwitch(io: Server, callId: string, newMode: 'p2p' | 'sfu') {
  io.to(`call:${callId}`).emit('CALL_MODE_SWITCH', {
    type: 'CALL_MODE_SWITCH',
    payload: { callId, newMode },
    timestamp: new Date(),
  });
}
