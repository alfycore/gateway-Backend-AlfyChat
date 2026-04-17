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
export declare const connectedClients: Map<string, ConnectedClient>;
/** Self-hosted server-nodes: serverId → ConnectedNode */
export declare const connectedNodes: Map<string, ConnectedNode>;
/** Voice channels: channelId → Map<userId, VoiceParticipant> */
export declare const voiceChannels: Map<string, Map<string, VoiceParticipant>>;
/** Each user can only be in one voice channel: userId → channelId */
export declare const userVoiceChannel: Map<string, string>;
//# sourceMappingURL=connections.d.ts.map