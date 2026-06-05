import { Server } from 'socket.io';
import { RedisClient } from './utils/redis';
import { ServiceProxy } from './services/proxy';
import { connectedNodes } from './state/connections';
declare let redis: RedisClient;
declare const io: Server<import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, any>;
declare const serviceProxy: ServiceProxy;
declare const serverNodesNs: import("socket.io").Namespace<import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, import("socket.io").DefaultEventsMap, any>;
export { io, redis, serviceProxy, connectedNodes, serverNodesNs };
//# sourceMappingURL=index.d.ts.map