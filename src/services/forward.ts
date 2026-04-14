// ==========================================
// ALFYCHAT — Forward events to server-nodes
// ==========================================

import { Socket } from 'socket.io';
import { connectedNodes } from '../state/connections';
import { runtime } from '../state/runtime';

/** Get the Socket.IO socket for a connected server-node */
export function getNodeSocket(serverId: string): Socket | null {
  const node = connectedNodes.get(serverId);
  if (!node) return null;
  const ns = runtime.io.of('/server-nodes');
  return ns.sockets.get(node.socketId) || null;
}

/** Forward an event to a server-node via acknowledge callback */
export function forwardToNode(
  serverId: string,
  event: string,
  data: any,
  timeoutMs = 15000,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const nodeSocket = getNodeSocket(serverId);
    if (!nodeSocket) return reject(new Error('NO_NODE'));
    const timer = setTimeout(() => {
      reject(new Error('NODE_TIMEOUT'));
    }, timeoutMs);
    nodeSocket.emit(event, data, (response: any) => {
      clearTimeout(timer);
      if (response?.error) return reject(new Error(response.error));
      resolve(response);
    });
  });
}
