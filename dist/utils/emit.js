"use strict";
// ==========================================
// ALFYCHAT - EMIT UTILITIES
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.emitToSocket = emitToSocket;
exports.emitError = emitError;
function emitToSocket(socket, type, payload) {
    socket.emit(type, {
        type,
        payload,
        timestamp: new Date(),
    });
}
function emitError(socket, type, error) {
    const message = error instanceof Error ? error.message : 'Une erreur est survenue';
    socket.emit('ERROR', {
        type,
        payload: { message },
        timestamp: new Date(),
    });
}
//# sourceMappingURL=emit.js.map