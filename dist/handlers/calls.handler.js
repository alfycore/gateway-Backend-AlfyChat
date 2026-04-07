"use strict";
// ==========================================
// ALFYCHAT - CALLS HANDLER
// Gestion des appels audio/vidéo
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerCallsHandlers = registerCallsHandlers;
const emit_1 = require("../utils/emit");
function registerCallsHandlers(socket, io, serviceProxy) {
    const userId = socket.userId;
    // Initier un appel
    socket.on('CALL_INITIATE', async (data) => {
        try {
            const call = await serviceProxy.calls.initiateCall({
                type: data.type,
                initiatorId: userId,
                conversationId: data.conversationId,
                channelId: data.channelId,
            });
            // Rejoindre la room de l'appel
            socket.join(`call:${call.id}`);
            // Notifier les participants
            if (data.conversationId) {
                io.to(`conversation:${data.conversationId}`).emit('CALL_INCOMING', {
                    type: 'CALL_INCOMING',
                    payload: call,
                    timestamp: new Date(),
                });
            }
            else if (data.channelId) {
                io.to(`channel:${data.channelId}`).emit('CALL_INCOMING', {
                    type: 'CALL_INCOMING',
                    payload: call,
                    timestamp: new Date(),
                });
            }
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'CALL_ERROR', error);
        }
    });
    // Accepter un appel
    socket.on('CALL_ACCEPT', async (data) => {
        try {
            const call = await serviceProxy.calls.joinCall(data.callId, userId);
            socket.join(`call:${data.callId}`);
            io.to(`call:${data.callId}`).emit('CALL_ACCEPT', {
                type: 'CALL_ACCEPT',
                payload: { callId: data.callId, userId },
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'CALL_ERROR', error);
        }
    });
    // Refuser un appel
    socket.on('CALL_REJECT', async (data) => {
        try {
            await serviceProxy.calls.rejectCall(data.callId, userId);
            io.to(`call:${data.callId}`).emit('CALL_REJECT', {
                type: 'CALL_REJECT',
                payload: { callId: data.callId, userId },
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'CALL_ERROR', error);
        }
    });
    // Terminer un appel
    socket.on('CALL_END', async (data) => {
        try {
            await serviceProxy.calls.endCall(data.callId, userId);
            io.to(`call:${data.callId}`).emit('CALL_END', {
                type: 'CALL_END',
                payload: { callId: data.callId },
                timestamp: new Date(),
            });
            socket.leave(`call:${data.callId}`);
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'CALL_ERROR', error);
        }
    });
    // Quitter un appel
    socket.on('CALL_LEAVE', async (data) => {
        try {
            await serviceProxy.calls.leaveCall(data.callId, userId);
            io.to(`call:${data.callId}`).emit('CALL_LEAVE', {
                type: 'CALL_LEAVE',
                payload: { callId: data.callId, userId },
                timestamp: new Date(),
            });
            socket.leave(`call:${data.callId}`);
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'CALL_ERROR', error);
        }
    });
    // Mute/Unmute audio
    socket.on('CALL_MUTE', async (data) => {
        io.to(`call:${data.callId}`).emit('CALL_MUTE', {
            type: 'CALL_MUTE',
            payload: { callId: data.callId, userId, muted: data.muted },
            timestamp: new Date(),
        });
    });
    // Activer/Désactiver vidéo
    socket.on('CALL_VIDEO_TOGGLE', async (data) => {
        io.to(`call:${data.callId}`).emit('CALL_VIDEO_TOGGLE', {
            type: 'CALL_VIDEO_TOGGLE',
            payload: { callId: data.callId, userId, videoEnabled: data.videoEnabled },
            timestamp: new Date(),
        });
    });
    // Partage d'écran
    socket.on('CALL_SCREEN_SHARE', async (data) => {
        io.to(`call:${data.callId}`).emit('CALL_SCREEN_SHARE', {
            type: 'CALL_SCREEN_SHARE',
            payload: { callId: data.callId, userId, sharing: data.sharing },
            timestamp: new Date(),
        });
    });
}
//# sourceMappingURL=calls.handler.js.map