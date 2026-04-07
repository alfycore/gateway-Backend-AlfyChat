// ==========================================
// ALFYCHAT - SERVERS HANDLER
// Gestion des événements de serveurs P2P
// ==========================================

import { Server as SocketServer } from 'socket.io';
import { AuthenticatedSocket } from '../types';
import { ServiceProxy } from '../services/proxy';
import { emitToSocket, emitError } from '../utils/emit';

interface ServerResponse {
  id: string;
  name: string;
  channels: { id: string }[];
  [key: string]: unknown;
}

export function registerServersHandlers(
  socket: AuthenticatedSocket,
  io: SocketServer,
  serviceProxy: ServiceProxy
): void {
  const userId = socket.userId!;

  // Rejoindre un serveur
  socket.on('SERVER_JOIN', async (data) => {
    try {
      const member = await serviceProxy.servers.joinServer(data.serverId, userId);
      
      socket.join(`server:${data.serverId}`);
      
      // Charger les channels et les rejoindre
      const server = await serviceProxy.servers.getServer(data.serverId);
      for (const channel of server.channels) {
        socket.join(`channel:${channel.id}`);
      }
      
      io.to(`server:${data.serverId}`).emit('MEMBER_JOIN', {
        type: 'MEMBER_JOIN',
        payload: { serverId: data.serverId, member },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // Quitter un serveur
  socket.on('SERVER_LEAVE', async (data) => {
    try {
      await serviceProxy.servers.leaveServer(data.serverId, userId);
      
      // Quitter les rooms
      socket.leave(`server:${data.serverId}`);
      const server = await serviceProxy.servers.getServer(data.serverId);
      for (const channel of server.channels) {
        socket.leave(`channel:${channel.id}`);
      }
      
      io.to(`server:${data.serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId: data.serverId, userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // Créer un serveur
  socket.on('SERVER_CREATE', async (data) => {
    try {
      const server = await serviceProxy.servers.createServer({
        name: data.name,
        description: data.description,
        ownerId: userId,
      }) as ServerResponse;
      
      socket.join(`server:${server.id}`);
      
      emitToSocket(socket, 'SERVER_CREATE_SUCCESS', server);
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // Mettre à jour un serveur
  socket.on('SERVER_UPDATE', async (data) => {
    try {
      const server = await serviceProxy.servers.updateServer(data.serverId, data.updates, userId);
      
      io.to(`server:${data.serverId}`).emit('SERVER_UPDATE', {
        type: 'SERVER_UPDATE',
        payload: server,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // Supprimer un serveur
  socket.on('SERVER_DELETE', async (data) => {
    try {
      await serviceProxy.servers.deleteServer(data.serverId, userId);
      
      io.to(`server:${data.serverId}`).emit('SERVER_DELETE', {
        type: 'SERVER_DELETE',
        payload: { serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // Créer un channel
  socket.on('CHANNEL_CREATE', async (data) => {
    try {
      const channel = await serviceProxy.servers.createChannel(data.serverId, {
        name: data.name,
        type: data.type,
      }, userId);
      
      io.to(`server:${data.serverId}`).emit('CHANNEL_CREATE', {
        type: 'CHANNEL_CREATE',
        payload: channel,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  // Mettre à jour un channel
  socket.on('CHANNEL_UPDATE', async (data) => {
    try {
      const channel = await serviceProxy.servers.updateChannel(data.channelId, data.updates, userId);
      
      io.to(`server:${data.serverId}`).emit('CHANNEL_UPDATE', {
        type: 'CHANNEL_UPDATE',
        payload: channel,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  // Supprimer un channel
  socket.on('CHANNEL_DELETE', async (data) => {
    try {
      await serviceProxy.servers.deleteChannel(data.serverId, data.channelId, userId);
      
      io.to(`server:${data.serverId}`).emit('CHANNEL_DELETE', {
        type: 'CHANNEL_DELETE',
        payload: { channelId: data.channelId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  // Kick un membre
  socket.on('MEMBER_KICK', async (data) => {
    try {
      await serviceProxy.servers.kickMember(data.serverId, data.userId, userId);
      
      io.to(`user:${data.userId}`).emit('SERVER_KICKED', {
        type: 'SERVER_KICKED',
        payload: { serverId: data.serverId },
        timestamp: new Date(),
      });
      
      io.to(`server:${data.serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId: data.serverId, userId: data.userId, kicked: true },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MEMBER_ERROR', error);
    }
  });

  // Obtenir les channels d'un serveur (réponse via callback socket.io)
  socket.on('SERVER_GET_CHANNELS', async (data, callback) => {
    try {
      const channels = await serviceProxy.servers.getServerChannels(data.serverId);
      if (typeof callback === 'function') callback({ channels: channels || [] });
    } catch (error) {
      if (typeof callback === 'function') callback({ channels: [], error: true });
    }
  });

  // Notification de mise à jour d'un serveur (broadcast seul, sans écriture DB)
  // Utilisé après un update HTTP pour propager le changement en temps réel.
  socket.on('SERVER_UPDATED_NOTIFY', (data) => {
    if (!data?.serverId) return;
    io.to(`server:${data.serverId}`).emit('SERVER_UPDATE', {
      type: 'SERVER_UPDATE',
      payload: { id: data.serverId, ...data },
      timestamp: new Date(),
    });
  });

  // Ban un membre
  socket.on('MEMBER_BAN', async (data) => {
    try {
      await serviceProxy.servers.banMember(data.serverId, data.userId, userId, data.reason);
      
      io.to(`user:${data.userId}`).emit('SERVER_BANNED', {
        type: 'SERVER_BANNED',
        payload: { serverId: data.serverId, reason: data.reason },
        timestamp: new Date(),
      });
      
      io.to(`server:${data.serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId: data.serverId, userId: data.userId, banned: true },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MEMBER_ERROR', error);
    }
  });
}
