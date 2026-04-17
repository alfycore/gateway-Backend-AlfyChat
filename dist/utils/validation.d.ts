export declare class ValidationError extends Error {
    field: string;
    constructor(field: string, message: string);
}
export declare const LIMITS: {
    readonly displayName: {
        readonly min: 1;
        readonly max: 32;
    };
    readonly username: {
        readonly min: 1;
        readonly max: 32;
    };
    readonly bio: {
        readonly min: 0;
        readonly max: 500;
    };
    readonly customStatus: {
        readonly min: 0;
        readonly max: 100;
    };
    readonly interests: {
        readonly maxItems: 10;
        readonly itemMin: 1;
        readonly itemMax: 24;
    };
    readonly messageContent: {
        readonly min: 1;
        readonly max: 4000;
    };
    readonly groupName: {
        readonly min: 1;
        readonly max: 64;
    };
    readonly serverName: {
        readonly min: 1;
        readonly max: 64;
    };
    readonly serverDescription: {
        readonly min: 0;
        readonly max: 500;
    };
    readonly channelName: {
        readonly min: 1;
        readonly max: 64;
    };
    readonly channelTopic: {
        readonly min: 0;
        readonly max: 200;
    };
    readonly roleName: {
        readonly min: 1;
        readonly max: 32;
    };
    readonly nickname: {
        readonly min: 0;
        readonly max: 32;
    };
    readonly customSlug: {
        readonly min: 3;
        readonly max: 32;
    };
    readonly inviteMaxUses: {
        readonly min: 1;
        readonly max: 1000;
    };
    readonly inviteExpiresIn: {
        readonly min: 60;
        readonly max: number;
    };
    readonly attachmentsCount: {
        readonly max: 10;
    };
    readonly tags: {
        readonly maxItems: 5;
        readonly itemMin: 1;
        readonly itemMax: 30;
    };
    readonly participants: {
        readonly max: 100;
    };
    readonly roleIds: {
        readonly max: 50;
    };
};
export declare function containsProfanity(text: string): boolean;
export declare function sanitizeText(text: string): string;
interface TextOpts {
    field: string;
    min?: number;
    max: number;
    required?: boolean;
    allowProfanity?: boolean;
    sanitize?: boolean;
}
export declare function validateText(value: unknown, opts: TextOpts): string | undefined;
interface ArrayOpts {
    field: string;
    max: number;
    itemMin?: number;
    itemMax?: number;
    dedupe?: boolean;
    allowProfanity?: boolean;
}
export declare function validateStringArray(value: unknown, opts: ArrayOpts): string[] | undefined;
export declare function validateInt(value: unknown, field: string, min: number, max: number, required?: boolean): number | undefined;
export declare function validateBool(value: unknown, field: string): boolean | undefined;
export declare function validateUrl(value: unknown, field: string, maxLen?: number): string | undefined;
export declare function validateSlug(value: unknown, field: string, min: number, max: number): string | undefined;
export declare function validateProfile(data: any): Record<string, unknown>;
export declare function validateGroupInput(data: any): {
    name?: string;
    avatarUrl?: string;
    participantIds?: string[];
    addParticipants?: string[];
    removeParticipants?: string[];
};
export declare function validateServerInput(data: any): {
    name?: string;
    description?: string;
    iconUrl?: string;
    bannerUrl?: string;
    isPublic?: boolean;
};
export declare function validateChannelInput(data: any): {
    name?: string;
    topic?: string;
    type?: string;
    parentId?: string;
};
export declare function validateRoleInput(data: any): {
    name?: string;
    color?: string;
};
export declare function validateMemberUpdate(data: any): {
    nickname?: string;
    roleIds?: string[];
};
export declare function validateMessageContent(content: unknown, attachments?: unknown): {
    content: string;
    attachments?: string[];
};
export declare function validateInviteInput(data: any): {
    maxUses?: number;
    expiresIn?: number;
    customSlug?: string;
    isPermanent?: boolean;
};
export declare function validateTags(value: unknown): string[] | undefined;
export {};
//# sourceMappingURL=validation.d.ts.map