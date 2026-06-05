interface ServiceUrls {
    users: string;
    messages: string;
    friends: string;
    calls: string;
    servers: string;
    bots: string;
    mediaServer?: string;
}
export declare class ServiceProxy {
    users: UsersProxy;
    messages: MessagesProxy;
    friends: FriendsProxy;
    calls: CallsProxy;
    servers: ServersProxy;
    bots: BotsProxy;
    media: MediaServerProxy;
    constructor(urls: ServiceUrls);
}
declare class UsersProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    getUser(userId: string): Promise<unknown>;
    updateStatus(userId: string, status: string, customStatus?: string | null, emoji?: string | null): Promise<unknown>;
    updateLastSeen(userId: string): Promise<unknown>;
    getPreferences(userId: string, _token?: string): Promise<unknown>;
    updateProfile(userId: string, data: Record<string, unknown>, _token?: string): Promise<unknown>;
    changeUsername(userId: string, newUsername: string, password: string, token?: string): Promise<unknown>;
    sendPushNotification(payload: {
        userId: string;
        title: string;
        body: string;
        url?: string;
        type?: string;
        conversationKey?: string;
    }): Promise<void>;
}
declare class MessagesProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    getConversations(userId: string, token?: string): Promise<any[]>;
    isParticipant(conversationId: string, userId: string): Promise<boolean>;
    createMessage(data: {
        id?: string;
        conversationId: string;
        senderId: string;
        content: string;
        senderContent?: string;
        e2eeType?: number;
        replyToId?: string;
    }): Promise<unknown>;
    updateMessage(messageId: string, content: string, userId: string, senderContent?: string, e2eeType?: number): Promise<unknown>;
    deleteMessage(messageId: string, userId: string): Promise<unknown>;
    addReaction(messageId: string, userId: string, emoji: string): Promise<unknown>;
    removeReaction(messageId: string, userId: string, emoji: string): Promise<unknown>;
    createConversation(data: {
        type: string;
        name?: string;
        avatarUrl?: string;
        participants: string[];
        createdBy: string;
        isOpen?: boolean;
    }): Promise<unknown>;
    updateConversation(conversationId: string, data: {
        name?: string;
        avatarUrl?: string;
        isOpen?: boolean;
    }, token?: string): Promise<unknown>;
    getConversationParticipants(conversationId: string): Promise<Array<{
        userId: string;
    }>>;
    addParticipant(conversationId: string, userId: string, token?: string): Promise<unknown>;
    removeParticipant(conversationId: string, userId: string, token?: string): Promise<unknown>;
    leaveConversation(conversationId: string, userId: string, token?: string): Promise<unknown>;
    deleteConversation(conversationId: string, token?: string): Promise<unknown>;
    getArchiveStatus(conversationId: string, token?: string): Promise<unknown>;
    getArchiveStats(conversationId: string, token?: string): Promise<unknown>;
    checkArchiveQuota(conversationId: string, token?: string): Promise<unknown>;
    confirmArchive(conversationId: string, archiveLogId: string, token?: string): Promise<unknown>;
    getCachedArchivedMessage(messageId: string, token?: string): Promise<unknown>;
    cacheArchivedMessages(messages: any[]): Promise<unknown>;
    saveNotification(userId: string, conversationId: string, senderName: string, senderId?: string, notificationType?: 'message' | 'mention', channelName?: string): Promise<unknown>;
    getNotifications(userId: string, token: string): Promise<unknown>;
}
declare class FriendsProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    getFriends(userId: string): Promise<any[]>;
    sendFriendRequest(fromUserId: string, toUserId: string, message?: string): Promise<unknown>;
    acceptFriendRequest(requestId: string, userId: string): Promise<unknown>;
    declineFriendRequest(requestId: string, userId: string): Promise<unknown>;
    rejectFriendRequest(requestId: string, userId: string): Promise<unknown>;
    removeFriend(userId: string, friendId: string): Promise<unknown>;
    blockUser(userId: string, blockedUserId: string): Promise<unknown>;
    unblockUser(userId: string, blockedUserId: string): Promise<unknown>;
}
declare class CallsProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    private internalHeaders;
    initiateCall(data: {
        type: string;
        initiatorId: string;
        conversationId?: string;
        channelId?: string;
        recipientId?: string;
    }): Promise<unknown>;
    joinCall(callId: string, userId: string): Promise<unknown>;
    getCall(callId: string): Promise<{
        id: string;
        participants: string[];
        status: string;
    } | null>;
    rejectCall(callId: string, userId: string): Promise<unknown>;
    endCall(callId: string, userId: string): Promise<unknown>;
    leaveCall(callId: string, userId: string): Promise<unknown>;
    createDmCall(data: {
        type: string;
        initiatorId: string;
        conversationId?: string;
    }): Promise<{
        id: string;
        callCategory: string;
        participants: string[];
    }>;
    createGroupCall(data: {
        channelId: string;
        initiatorId: string;
        type: string;
    }): Promise<{
        id: string;
        callId?: string;
        callCategory: string;
        channelId: string;
        type: string;
        status: string;
        participants: string[];
    }>;
    createServerCall(data: {
        channelId: string;
        serverId: string;
        initiatorId: string;
        type: string;
    }): Promise<{
        id: string;
        callCategory: string;
        channelId: string;
        serverId: string;
        status: string;
        participants: string[];
    }>;
    getCallQuality(callId: string): Promise<{
        callId: string;
        tier: number;
        participantCount: number;
        callCategory: string;
    }>;
    getServerLimit(serverId: string): Promise<number>;
}
declare class MediaServerProxy {
    private baseUrl;
    constructor(baseUrl: string);
    private headers;
    private post;
    private del;
    private get;
    createRoom(callId: string, callCategory: 'group' | 'server'): Promise<unknown>;
    destroyRoom(callId: string): Promise<void>;
    getRtpCapabilities(callId: string): Promise<{
        rtpCapabilities: unknown;
    }>;
    createTransport(callId: string, userId: string, direction: 'send' | 'recv'): Promise<{
        transportId: string;
        iceParameters: unknown;
        iceCandidates: unknown;
        dtlsParameters: unknown;
    }>;
    connectTransport(callId: string, transportId: string, dtlsParameters: unknown): Promise<unknown>;
    produce(callId: string, transportId: string, kind: string, rtpParameters: unknown, userId: string, appData?: unknown): Promise<{
        producerId: string;
    }>;
    consume(callId: string, recvTransportId: string, producerId: string, rtpCapabilities: unknown, userId: string): Promise<{
        consumerId: string;
        producerId: string;
        kind: string;
        rtpParameters: unknown;
        paused: boolean;
    }>;
    resumeConsumer(callId: string, consumerId: string): Promise<unknown>;
    closeProducer(callId: string, producerId: string): Promise<unknown>;
    getRoomStats(callId: string): Promise<{
        participantCount: number;
        tier: number;
    }>;
    getProducers(callId: string): Promise<{
        producers: {
            producerId: string;
            userId: string;
            kind: string;
        }[];
    }>;
}
declare class ServersProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    getUserServers(userId: string, token?: string): Promise<any[]>;
    getServer(serverId: string): Promise<any>;
    getServerChannels(serverId: string, userId?: string): Promise<any[]>;
    joinServer(serverId: string, userId: string): Promise<unknown>;
    leaveServer(serverId: string, userId: string): Promise<unknown>;
    registerServerHost(data: {
        serverId: string;
        endpoint: string;
        port: number;
        publicKey: string;
    }): Promise<unknown>;
    createServer(data: {
        name: string;
        description?: string;
        ownerId: string;
    }): Promise<unknown>;
    updateServer(serverId: string, updates: any, userId: string, token?: string): Promise<unknown>;
    deleteServer(serverId: string, userId: string, token?: string): Promise<unknown>;
    createChannel(serverId: string, data: {
        name: string;
        type: string;
        parentId?: string;
    }, userId: string, token?: string): Promise<unknown>;
    updateChannel(serverId: string, channelId: string, updates: any, userId: string, token?: string): Promise<unknown>;
    deleteChannel(serverId: string, channelId: string, userId: string, token?: string): Promise<unknown>;
    kickMember(serverId: string, memberUserId: string, requesterId: string): Promise<unknown>;
    banMember(serverId: string, memberUserId: string, requesterId: string, reason?: string): Promise<unknown>;
    getChannelMessages(serverId: string, channelId: string, limit?: number, before?: string): Promise<any[]>;
    createServerMessage(serverId: string, channelId: string, data: {
        senderId: string;
        content: string;
        attachments?: string[];
        replyToId?: string;
        tags?: string[];
    }): Promise<unknown>;
    editServerMessage(serverId: string, messageId: string, content: string, senderId: string): Promise<unknown>;
    deleteServerMessage(serverId: string, messageId: string, senderId: string): Promise<unknown>;
    addServerReaction(serverId: string, messageId: string, userId: string, emoji: string): Promise<unknown>;
    removeServerReaction(serverId: string, messageId: string, userId: string, emoji: string): Promise<unknown>;
    getMembers(serverId: string): Promise<any[]>;
    updateMember(serverId: string, memberUserId: string, data: {
        roleIds?: string[];
        nickname?: string;
    }, actorId?: string, token?: string): Promise<unknown>;
    isMember(serverId: string, userId: string): Promise<boolean>;
    getRoles(serverId: string): Promise<any[]>;
    createRole(serverId: string, data: {
        name: string;
        color?: string;
        permissions?: any;
    }, userId?: string): Promise<unknown>;
    updateRole(serverId: string, roleId: string, data: any, userId?: string): Promise<unknown>;
    deleteRole(serverId: string, roleId: string, userId?: string): Promise<unknown>;
    createInvite(serverId: string, data: {
        creatorId: string;
        maxUses?: number;
        expiresIn?: number;
        customSlug?: string;
        isPermanent?: boolean;
        code?: string;
        id?: string;
    }): Promise<unknown>;
    getInvites(serverId: string): Promise<any[]>;
    resolveInvite(code: string): Promise<unknown>;
    joinByInvite(inviteCode: string, userId: string): Promise<unknown>;
    validateNodeToken(nodeToken: string): Promise<unknown>;
    registerNode(name?: string): Promise<unknown>;
}
declare class BotsProxy {
    private _fallbackUrl;
    constructor(_fallbackUrl: string);
    private get baseUrl();
    getBot(botId: string): Promise<unknown>;
    validateBotToken(token: string): Promise<unknown>;
}
export {};
//# sourceMappingURL=proxy.d.ts.map