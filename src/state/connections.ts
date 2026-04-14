// ==========================================
// ALFYCHAT — Shared Connection State
// ==========================================

import { Socket } from 'socket.io';

export interface ConnectedClient {
  socketId: string;
  userId: string;
  sessionId: string;
  connectedAt: Date;
}

export interface ConnectedNode {
  socketId: string;
  serverId: string;
  endpoint?: string;
  connectedAt: Date;
}

export interface VoiceParticipant {
  socketId: string;
  userId: string;
  username: string;
  avatarUrl?: string;
  muted: boolean;
  deafened: boolean;
  serverId: string;
}

/** Active WebSocket clients: socket.id → ConnectedClient */
export const connectedClients = new Map<string, ConnectedClient>();

/** Self-hosted server-nodes: serverId → ConnectedNode */
export const connectedNodes = new Map<string, ConnectedNode>();

/** Voice channels: channelId → Map<userId, VoiceParticipant> */
export const voiceChannels = new Map<string, Map<string, VoiceParticipant>>();

/** Each user can only be in one voice channel: userId → channelId */
export const userVoiceChannel = new Map<string, string>();
