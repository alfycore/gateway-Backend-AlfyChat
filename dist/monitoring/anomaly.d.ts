import type { Request, Response, NextFunction } from 'express';
import type { Socket } from 'socket.io';
/**
 * Attach after rate-limit middleware. Records request stats asynchronously
 * once the response has been flushed — zero impact on response latency.
 */
export declare function anomalyMiddleware(req: Request, res: Response, next: NextFunction): void;
/**
 * Attach to a socket after successful authentication.
 * Counts non-trivial WS events toward the anomaly score of the userId.
 */
export declare function attachAnomalyWsHooks(socket: Socket, userId: string): void;
//# sourceMappingURL=anomaly.d.ts.map