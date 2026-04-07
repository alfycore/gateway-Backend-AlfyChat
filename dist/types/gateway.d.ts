import { Socket } from 'socket.io';
export interface User {
    id: string;
    username: string;
    email: string;
    displayName?: string;
    avatarUrl?: string;
    status: UserStatus;
    bio?: string;
    createdAt: Date;
    updatedAt: Date;
}
export type UserStatus = 'online' | 'idle' | 'dnd' | 'invisible' | 'offline';
export interface AuthenticatedSocket extends Socket {
    userId?: string;
    sessionId?: string;
    user?: User;
}
export interface ConnectedClient {
    socketId: string;
    userId: string;
    sessionId: string;
    connectedAt: Date;
}
export type GatewayEventType = string;
export interface GatewayEvent {
    type: string;
    payload: unknown;
    timestamp: Date;
}
export interface Server {
    id: string;
    name: string;
    iconUrl?: string;
    ownerId: string;
    channels: Channel[];
}
export interface Channel {
    id: string;
    serverId: string;
    name: string;
    type: 'text' | 'voice' | 'announcement';
}
export interface Conversation {
    id: string;
    type: 'dm' | 'group';
    participants: string[];
}
export interface Friend {
    id: string;
    friendId: string;
    username: string;
}
export interface Call {
    id: string;
    type: 'audio' | 'video';
    initiatorId: string;
    participants: string[];
    status: 'ringing' | 'ongoing' | 'ended';
}
export interface Message {
    id: string;
    conversationId: string;
    senderId: string;
    content: string;
    createdAt: Date;
}
export interface FriendRequest {
    id: string;
    fromUserId: string;
    toUserId: string;
    status: 'pending' | 'accepted' | 'rejected';
}
export interface Friendship {
    id: string;
    userId: string;
    friendId: string;
}
//# sourceMappingURL=gateway.d.ts.map