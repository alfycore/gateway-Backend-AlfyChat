"use strict";
// ==========================================
// ALFYCHAT - WEBRTC HANDLER
// Signaling WebRTC pour les appels P2P
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerWebRTCHandlers = registerWebRTCHandlers;
function registerWebRTCHandlers(socket, io) {
    const userId = socket.userId;
    // Offre WebRTC
    socket.on('WEBRTC_OFFER', (data) => {
        socket.to(`call:${data.callId}`).emit('WEBRTC_OFFER', {
            type: 'WEBRTC_OFFER',
            payload: { ...data, fromUserId: userId },
            timestamp: new Date(),
        });
    });
    // Réponse WebRTC
    socket.on('WEBRTC_ANSWER', (data) => {
        socket.to(`call:${data.callId}`).emit('WEBRTC_ANSWER', {
            type: 'WEBRTC_ANSWER',
            payload: { ...data, fromUserId: userId },
            timestamp: new Date(),
        });
    });
    // Candidat ICE
    socket.on('WEBRTC_ICE_CANDIDATE', (data) => {
        socket.to(`call:${data.callId}`).emit('WEBRTC_ICE_CANDIDATE', {
            type: 'WEBRTC_ICE_CANDIDATE',
            payload: { ...data, fromUserId: userId },
            timestamp: new Date(),
        });
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
//# sourceMappingURL=webrtc.handler.js.map