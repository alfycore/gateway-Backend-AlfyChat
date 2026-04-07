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
  const message = error instanceof Error ? error.message : 'Une erreur est survenue';
  socket.emit('ERROR', {
    type,
    payload: { message },
    timestamp: new Date(),
  });
}
