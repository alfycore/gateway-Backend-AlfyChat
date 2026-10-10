// ==========================================
// ALFYCHAT - EMIT UTILITIES
// ==========================================

import { Socket } from 'socket.io';
import { GatewayEvent } from '../types';

export function emitToSocket(socket: Socket, type: string, payload: unknown): void {
  socket.emit(type, {
    type,
    payload,
    timestamp: new Date(),
  } as GatewayEvent);
}

export function emitError(socket: Socket, type: string, error: unknown): void {
  let message = error instanceof Error ? error.message : 'Une erreur est survenue';
  // Pas de détail interne côté client (corps bruts du media-server / des services).
  if (/^media-server /.test(message)) message = 'Opération refusée';
  const m = /^Service error: (\d{3}) (.*)$/s.exec(message);
  if (m) {
    let clean = `Erreur ${m[1]}`;
    try {
      const body = JSON.parse(m[2]);
      if (typeof body?.error === 'string') clean = body.error;
    } catch { /* corps non JSON */ }
    message = clean;
  }
  socket.emit('ERROR', {
    type,
    payload: { message },
    timestamp: new Date(),
  });
}
