"use strict";
// ==========================================
// ALFYCHAT - CALLS HANDLER
// Gestion des appels audio/vidéo
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerCallsHandlers = registerCallsHandlers;
const emit_1 = require("../utils/emit");
// ── Séparation DM calls (WebRTC P2P) vs Group calls (LiveKit SFU)
// DM calls      → CALL_INITIATE / CALL_ACCEPT / CALL_REJECT / CALL_END / CALL_LEAVE
// Group calls   → GROUP_CALL_INITIATE / GROUP_CALL_JOIN / GROUP_CALL_LEAVE / GROUP_CALL_END
function registerCallsHandlers(socket, io, serviceProxy) {
    const userId = socket.userId;
    const username = socket.username || userId;
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
            // Notifier TOUS les participants existants qu'un nouveau pair a rejoint
            // → chaque participant existant créera un PeerConnection vers ce nouvel arrivant
            socket.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_JOINED', {
                type: 'CALL_PARTICIPANT_JOINED',
                payload: { callId: data.callId, userId },
                timestamp: new Date(),
            });
            // Confirmer à l'appelant que l'appel est accepté
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
    // ════════════════════════════════════════════════════════
    //  APPELS GROUPE — LiveKit SFU
    //  Séparés des appels DM P2P : topologie SFU, pas mesh.
    // ════════════════════════════════════════════════════════
    /** Initier un appel groupe dans un canal serveur */
    socket.on('GROUP_CALL_INITIATE', async (data) => {
        try {
            const roomData = await serviceProxy.calls.createGroupRoom({
                channelId: data.channelId,
                participantId: userId,
                participantName: username,
                type: data.type || 'voice',
            });
            // Rejoindre la room Socket.IO de coordination
            socket.join(`group_call:${roomData.callId}`);
            // Notifier tous les membres du canal qu'un appel groupe est disponible
            io.to(`channel:${data.channelId}`).emit('GROUP_CALL_INCOMING', {
                type: 'GROUP_CALL_INCOMING',
                payload: {
                    callId: roomData.callId,
                    channelId: data.channelId,
                    initiatorId: userId,
                    initiatorName: username,
                    callType: data.type || 'voice',
                },
                timestamp: new Date(),
            });
            // Retourner le token LiveKit à l'initiateur
            socket.emit('GROUP_CALL_TOKEN', {
                callId: roomData.callId,
                token: roomData.token,
                wsUrl: roomData.wsUrl,
                roomName: roomData.roomName,
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'GROUP_CALL_ERROR', error);
        }
    });
    /** Rejoindre un appel groupe existant */
    socket.on('GROUP_CALL_JOIN', async (data) => {
        try {
            const tokenData = await serviceProxy.calls.getGroupCallToken({
                callId: data.callId,
                participantId: userId,
                participantName: username,
            });
            socket.join(`group_call:${data.callId}`);
            // Notifier les autres participants
            socket.to(`group_call:${data.callId}`).emit('GROUP_CALL_PARTICIPANT_JOINED', {
                type: 'GROUP_CALL_PARTICIPANT_JOINED',
                payload: { callId: data.callId, userId, username },
                timestamp: new Date(),
            });
            // Envoyer le token au nouvel arrivant
            socket.emit('GROUP_CALL_TOKEN', {
                callId: data.callId,
                token: tokenData.token,
                wsUrl: tokenData.wsUrl,
                roomName: tokenData.roomName,
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'GROUP_CALL_ERROR', error);
        }
    });
    /** Quitter un appel groupe */
    socket.on('GROUP_CALL_LEAVE', (data) => {
        socket.leave(`group_call:${data.callId}`);
        socket.to(`group_call:${data.callId}`).emit('GROUP_CALL_PARTICIPANT_LEFT', {
            type: 'GROUP_CALL_PARTICIPANT_LEFT',
            payload: { callId: data.callId, userId, username },
            timestamp: new Date(),
        });
    });
    /** Terminer un appel groupe (initiateur / admin) */
    socket.on('GROUP_CALL_END', async (data) => {
        try {
            await serviceProxy.calls.endGroupCall(data.callId);
            io.to(`group_call:${data.callId}`).emit('GROUP_CALL_ENDED', {
                type: 'GROUP_CALL_ENDED',
                payload: { callId: data.callId, endedBy: userId },
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'GROUP_CALL_ERROR', error);
        }
    });
}
//# sourceMappingURL=calls.handler.js.map