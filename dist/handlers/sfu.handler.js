"use strict";
// ==========================================
// ALFYCHAT - SFU HANDLER (mediasoup relay)
// Relay des events Socket.IO vers le media-server
// pour les appels groupe (>10 participants) et serveur (≤1500).
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.GROUP_SFU_THRESHOLD = void 0;
exports.registerSfuHandlers = registerSfuHandlers;
exports.broadcastQualityUpdate = broadcastQualityUpdate;
exports.broadcastModeSwitch = broadcastModeSwitch;
const emit_1 = require("../utils/emit");
// Redis key : call:mode:<callId> → 'p2p' | 'sfu'
exports.GROUP_SFU_THRESHOLD = parseInt(process.env.GROUP_SFU_THRESHOLD || '10');
function registerSfuHandlers(socket, io, serviceProxy) {
    const userId = socket.userId;
    // ── RTP Capabilities ────────────────────────────────────────────────────────
    // Client a besoin des codecs supportés par le router pour créer son Device mediasoup-client
    socket.on('SFU_GET_RTP_CAPABILITIES', async (data, callback) => {
        try {
            const result = await serviceProxy.media.getRtpCapabilities(data.callId);
            if (typeof callback === 'function')
                callback(result);
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
            if (typeof callback === 'function')
                callback({ error: 'Impossible de récupérer les capabilities' });
        }
    });
    // ── Transport ───────────────────────────────────────────────────────────────
    socket.on('SFU_CREATE_TRANSPORT', async (data, callback) => {
        try {
            const result = await serviceProxy.media.createTransport(data.callId, userId, data.direction);
            if (typeof callback === 'function')
                callback(result);
            else
                socket.emit('SFU_TRANSPORT_CREATED', { ...result, callId: data.callId });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
            if (typeof callback === 'function')
                callback({ error: 'Erreur création transport' });
        }
    });
    socket.on('SFU_CONNECT_TRANSPORT', async (data, callback) => {
        try {
            await serviceProxy.media.connectTransport(data.callId, data.transportId, data.dtlsParameters);
            if (typeof callback === 'function')
                callback({ success: true });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
            if (typeof callback === 'function')
                callback({ error: 'Erreur connexion transport' });
        }
    });
    // ── Producers ───────────────────────────────────────────────────────────────
    socket.on('SFU_PRODUCE', async (data, callback) => {
        try {
            const result = await serviceProxy.media.produce(data.callId, data.transportId, data.kind, data.rtpParameters, userId, data.appData);
            if (typeof callback === 'function')
                callback(result);
            else
                socket.emit('SFU_PRODUCED', { ...result, callId: data.callId });
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
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
            if (typeof callback === 'function')
                callback({ error: 'Erreur création producer' });
        }
    });
    socket.on('SFU_CLOSE_PRODUCER', async (data) => {
        try {
            await serviceProxy.media.closeProducer(data.callId, data.producerId);
            socket.to(`call:${data.callId}`).emit('SFU_PRODUCER_CLOSED', {
                type: 'SFU_PRODUCER_CLOSED',
                payload: { callId: data.callId, producerId: data.producerId, userId },
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
        }
    });
    // ── Consumers ───────────────────────────────────────────────────────────────
    socket.on('SFU_CONSUME', async (data, callback) => {
        try {
            const result = await serviceProxy.media.consume(data.callId, data.recvTransportId, data.producerId, data.rtpCapabilities, userId);
            if (typeof callback === 'function')
                callback(result);
            else
                socket.emit('SFU_CONSUMED', { ...result, callId: data.callId });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
            if (typeof callback === 'function')
                callback({ error: 'Erreur création consumer' });
        }
    });
    socket.on('SFU_RESUME_CONSUMER', async (data, callback) => {
        try {
            await serviceProxy.media.resumeConsumer(data.callId, data.consumerId);
            if (typeof callback === 'function')
                callback({ success: true });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'SFU_ERROR', error);
        }
    });
    // ── Raise / Lower hand (appels serveur) ─────────────────────────────────────
    socket.on('CALL_RAISE_HAND', (data) => {
        socket.to(`call:${data.callId}`).emit('CALL_HAND_RAISED', {
            type: 'CALL_HAND_RAISED',
            payload: { callId: data.callId, userId },
            timestamp: new Date(),
        });
    });
    socket.on('CALL_LOWER_HAND', (data) => {
        socket.to(`call:${data.callId}`).emit('CALL_HAND_LOWERED', {
            type: 'CALL_HAND_LOWERED',
            payload: { callId: data.callId, userId },
            timestamp: new Date(),
        });
    });
}
// ── Broadcast d'un update de qualité depuis le media-server ─────────────────
// Appelé par l'endpoint HTTP /internal/call-quality dans index.ts
function broadcastQualityUpdate(io, callId, tier, participantCount, tierParams) {
    io.to(`call:${callId}`).emit('CALL_QUALITY_UPDATE', {
        type: 'CALL_QUALITY_UPDATE',
        payload: { callId, tier, participantCount, tierParams },
        timestamp: new Date(),
    });
}
// ── Broadcast d'un switch P2P→SFU ───────────────────────────────────────────
function broadcastModeSwitch(io, callId, newMode) {
    io.to(`call:${callId}`).emit('CALL_MODE_SWITCH', {
        type: 'CALL_MODE_SWITCH',
        payload: { callId, newMode },
        timestamp: new Date(),
    });
}
//# sourceMappingURL=sfu.handler.js.map