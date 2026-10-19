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
  displayName?: string;
  avatarUrl?: string;
  /** Micro coupé par l'utilisateur. */
  muted: boolean;
  /** Son coupé par l'utilisateur. */
  deafened: boolean;
  serverId: string;
  /** Caméra active. */
  video?: boolean;
  /** Partage d'écran en cours (« EN DIRECT »). */
  streaming?: boolean;
  /** Rendu muet / sourd par un modérateur. */
  serverMuted?: boolean;
  serverDeafened?: boolean;
  joinedAt?: number;
}

/** Statut libre d'un salon vocal (« Définir un statut de salon ») : channelId → texte. */
export const voiceChannelStatus = new Map<string, string>();

/** Active WebSocket clients: socket.id → ConnectedClient */
export const connectedClients = new Map<string, ConnectedClient>();

/** Self-hosted server-nodes: serverId → ConnectedNode */
export const connectedNodes = new Map<string, ConnectedNode>();

/** Voice channels: channelId → Map<userId, VoiceParticipant> */
export const voiceChannels = new Map<string, Map<string, VoiceParticipant>>();

/** Each user can only be in one voice channel: userId → channelId */
export const userVoiceChannel = new Map<string, string>();
