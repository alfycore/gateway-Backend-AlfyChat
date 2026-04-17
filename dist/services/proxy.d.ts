interface ServiceUrls {
    users: string;
    messages: string;
    friends: string;
    calls: string;
    servers: string;
    bots: string;
}
export declare class ServiceProxy {
    users: UsersProxy;
    messages: MessagesProxy;
    friends: FriendsProxy;
    calls: CallsProxy;
    servers: ServersProxy;
    bots: BotsProxy;
    constructor(urls: ServiceUrls);
}
declare class UsersProxy {
    private baseUrl;
    constructor(baseUrl: string);
    getUser(userId: string): Promise<unknown>;
    updateStatus(userId: string, status: string, customStatus?: string): Promise<unknown>;
    updateLastSeen(userId: string): Promise<unknown>;
    getPreferences(userId: string, token?: string): Promise<unknown>;
    updateProfile(userId: string, data: Record<string, unknown>, token?: string): Promise<unknown>;
}
declare class MessagesProxy {
    private baseUrl;
    constructor(baseUrl: string);
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
    updateMessage(messageId: string, content: string, userId: string): Promise<unknown>;
    deleteMessage(messageId: string, userId: string): Promise<unknown>;
    addReaction(messageId: string, userId: string, emoji: string): Promise<unknown>;
    removeReaction(messageId: string, userId: string, emoji: string): Promise<unknown>;
    createConversation(data: {
        type: string;
        name?: string;
        avatarUrl?: string;
        participants: string[];
        createdBy: string;
    }): Promise<unknown>;
    updateConversation(conversationId: string, data: {
        name?: string;
        avatarUrl?: string;
    }, token?: string): Promise<unknown>;
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
    saveNotification(userId: string, conversationId: string, senderName: string): Promise<unknown>;
    getNotifications(userId: string, token: string): Promise<unknown>;
}
declare class FriendsProxy {
    private baseUrl;
    constructor(baseUrl: string);
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
    private baseUrl;
    constructor(baseUrl: string);
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
    createGroupRoom(data: {
        channelId: string;
        participantId: string;
        participantName: string;
        type: string;
    }): Promise<{
        callId: string;
        roomName: string;
        token: string;
        wsUrl: string;
    }>;
    getGroupCallToken(data: {
        callId: string;
        participantId: string;
        participantName: string;
    }): Promise<{
        token: string;
        roomName: string;
        wsUrl: string;
    }>;
    endGroupCall(callId: string): Promise<unknown>;
}
declare class ServersProxy {
    private baseUrl;
    constructor(baseUrl: string);
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
    updateServer(serverId: string, updates: any, userId: string): Promise<unknown>;
    deleteServer(serverId: string, userId: string): Promise<unknown>;
    createChannel(serverId: string, data: {
        name: string;
        type: string;
        parentId?: string;
    }, userId: string): Promise<unknown>;
    updateChannel(serverId: string, channelId: string, updates: any, userId: string): Promise<unknown>;
    deleteChannel(serverId: string, channelId: string, userId: string): Promise<unknown>;
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
    }): Promise<unknown>;
    isMember(serverId: string, userId: string): Promise<boolean>;
    getRoles(serverId: string): Promise<any[]>;
    createRole(serverId: string, data: {
        name: string;
        color?: string;
        permissions?: any;
    }): Promise<unknown>;
    updateRole(serverId: string, roleId: string, data: any): Promise<unknown>;
    deleteRole(serverId: string, roleId: string): Promise<unknown>;
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
    private baseUrl;
    constructor(baseUrl: string);
    getBot(botId: string): Promise<unknown>;
    validateBotToken(token: string): Promise<unknown>;
}
export {};
//# sourceMappingURL=proxy.d.ts.map