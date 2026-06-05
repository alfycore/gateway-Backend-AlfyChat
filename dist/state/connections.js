"use strict";
// ==========================================
// ALFYCHAT — Shared Connection State
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.userVoiceChannel = exports.voiceChannels = exports.connectedNodes = exports.connectedClients = void 0;
/** Active WebSocket clients: socket.id → ConnectedClient */
exports.connectedClients = new Map();
/** Self-hosted server-nodes: serverId → ConnectedNode */
exports.connectedNodes = new Map();
/** Voice channels: channelId → Map<userId, VoiceParticipant> */
exports.voiceChannels = new Map();
/** Each user can only be in one voice channel: userId → channelId */
exports.userVoiceChannel = new Map();
//# sourceMappingURL=connections.js.map