// ==========================================
// ALFYCHAT — Runtime Context (populated at startup)
// Route modules import this to access io / redis without closures.
// ==========================================

import type { Server } from 'socket.io';
import type { RedisClient } from '../utils/redis';

export const runtime = {
  io: null as unknown as Server,
  redis: null as unknown as RedisClient,
};
