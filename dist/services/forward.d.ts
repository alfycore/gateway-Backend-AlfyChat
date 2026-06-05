import { Socket } from 'socket.io';
/** Get the Socket.IO socket for a connected server-node */
export declare function getNodeSocket(serverId: string): Socket | null;
/** Forward an event to a server-node via acknowledge callback */
export declare function forwardToNode(serverId: string, event: string, data: any, timeoutMs?: number): Promise<any>;
//# sourceMappingURL=forward.d.ts.map