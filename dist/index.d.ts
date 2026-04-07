import { Server } from 'socket.io';
import { RedisClient } from './utils/redis';
import { ServiceProxy } from './services/proxy';
declare const io: Server<import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, any>;
declare const redis: RedisClient;
declare const serviceProxy: ServiceProxy;
declare const connectedNodes: Map<string, {
    socketId: string;
    serverId: string;
    endpoint?: string;
    connectedAt: Date;
}>;
declare const serverNodesNs: import("socket.io").Namespace<import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, any>;
export { io, redis, serviceProxy, connectedNodes, serverNodesNs };
//# sourceMappingURL=index.d.ts.map