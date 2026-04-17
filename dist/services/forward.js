"use strict";
// ==========================================
// ALFYCHAT — Forward events to server-nodes
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.getNodeSocket = getNodeSocket;
exports.forwardToNode = forwardToNode;
const connections_1 = require("../state/connections");
const runtime_1 = require("../state/runtime");
/** Get the Socket.IO socket for a connected server-node */
function getNodeSocket(serverId) {
    const node = connections_1.connectedNodes.get(serverId);
    if (!node)
        return null;
    const ns = runtime_1.runtime.io.of('/server-nodes');
    return ns.sockets.get(node.socketId) || null;
}
/** Forward an event to a server-node via acknowledge callback */
function forwardToNode(serverId, event, data, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
        const nodeSocket = getNodeSocket(serverId);
        if (!nodeSocket)
            return reject(new Error('NO_NODE'));
        const timer = setTimeout(() => {
            reject(new Error('NODE_TIMEOUT'));
        }, timeoutMs);
        nodeSocket.emit(event, data, (response) => {
            clearTimeout(timer);
            if (response?.error)
                return reject(new Error(response.error));
            resolve(response);
        });
    });
}
//# sourceMappingURL=forward.js.map