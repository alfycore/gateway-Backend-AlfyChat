import { Server } from 'socket.io';
import type { AuthenticatedSocket } from '../types';
import type { ServiceProxy } from '../services/proxy';
export declare const GROUP_SFU_THRESHOLD: number;
export declare function registerSfuHandlers(socket: AuthenticatedSocket, io: Server, serviceProxy: ServiceProxy): void;
export declare function broadcastQualityUpdate(io: Server, callId: string, tier: number, participantCount: number, tierParams: unknown): void;
export declare function broadcastModeSwitch(io: Server, callId: string, newMode: 'p2p' | 'sfu'): void;
//# sourceMappingURL=sfu.handler.d.ts.map