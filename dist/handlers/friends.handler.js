"use strict";
// ==========================================
// ALFYCHAT - FRIENDS HANDLER
// Gestion des événements d'amitié
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerFriendsHandlers = registerFriendsHandlers;
const emit_1 = require("../utils/emit");
function registerFriendsHandlers(socket, io, serviceProxy) {
    const userId = socket.userId;
    // Envoyer une demande d'ami
    socket.on('FRIEND_REQUEST', async (data) => {
        try {
            const request = await serviceProxy.friends.sendFriendRequest(userId, data.toUserId, data.message);
            // Notifier le destinataire
            io.to(`user:${data.toUserId}`).emit('FRIEND_REQUEST', {
                type: 'FRIEND_REQUEST',
                payload: request,
                timestamp: new Date(),
            });
            (0, emit_1.emitToSocket)(socket, 'FRIEND_REQUEST_SENT', request);
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'FRIEND_REQUEST_ERROR', error);
        }
    });
    // Accepter une demande d'ami
    socket.on('FRIEND_ACCEPT', async (data) => {
        try {
            const friendship = await serviceProxy.friends.acceptFriendRequest(data.requestId, userId);
            // Notifier les deux utilisateurs
            io.to(`user:${friendship.userId}`).emit('FRIEND_ACCEPT', {
                type: 'FRIEND_ACCEPT',
                payload: friendship,
                timestamp: new Date(),
            });
            io.to(`user:${friendship.friendId}`).emit('FRIEND_ACCEPT', {
                type: 'FRIEND_ACCEPT',
                payload: friendship,
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'FRIEND_ACCEPT_ERROR', error);
        }
    });
    // Refuser une demande d'ami
    socket.on('FRIEND_REJECT', async (data) => {
        try {
            await serviceProxy.friends.rejectFriendRequest(data.requestId, userId);
            (0, emit_1.emitToSocket)(socket, 'FRIEND_REJECT_SUCCESS', { requestId: data.requestId });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'FRIEND_REJECT_ERROR', error);
        }
    });
    // Supprimer un ami
    socket.on('FRIEND_REMOVE', async (data) => {
        try {
            await serviceProxy.friends.removeFriend(userId, data.friendId);
            // Notifier les deux utilisateurs
            io.to(`user:${userId}`).emit('FRIEND_REMOVE', {
                type: 'FRIEND_REMOVE',
                payload: { friendId: data.friendId },
                timestamp: new Date(),
            });
            io.to(`user:${data.friendId}`).emit('FRIEND_REMOVE', {
                type: 'FRIEND_REMOVE',
                payload: { friendId: userId },
                timestamp: new Date(),
            });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'FRIEND_REMOVE_ERROR', error);
        }
    });
    // Bloquer un utilisateur
    socket.on('USER_BLOCK', async (data) => {
        try {
            await serviceProxy.friends.blockUser(userId, data.blockedUserId);
            (0, emit_1.emitToSocket)(socket, 'USER_BLOCK_SUCCESS', { blockedUserId: data.blockedUserId });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'USER_BLOCK_ERROR', error);
        }
    });
    // Débloquer un utilisateur
    socket.on('USER_UNBLOCK', async (data) => {
        try {
            await serviceProxy.friends.unblockUser(userId, data.blockedUserId);
            (0, emit_1.emitToSocket)(socket, 'USER_UNBLOCK_SUCCESS', { unblockedUserId: data.blockedUserId });
        }
        catch (error) {
            (0, emit_1.emitError)(socket, 'USER_UNBLOCK_ERROR', error);
        }
    });
}
//# sourceMappingURL=friends.handler.js.map