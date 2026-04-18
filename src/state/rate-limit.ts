// ==========================================
// ALFYCHAT — WS Message & Join Rate Limiting
// ==========================================

/** userId → array of timestamps (last N messages) */
export const messageRateLimit = new Map<string, number[]>();
export const MSG_RATE_WINDOW = 10000; // 10 seconds
export const MSG_RATE_MAX = 10;       // max 10 messages per window

/** SERVER_JOIN / SERVER_LEAVE rate limit */
export const serverJoinRateLimit = new Map<string, number[]>();
export const JOIN_RATE_WINDOW = 60000; // 60 seconds
export const JOIN_RATE_MAX = 5;        // max 5 join/leave per minute

export function checkServerJoinRate(userId: string): boolean {
  const now = Date.now();
  const timestamps = serverJoinRateLimit.get(userId) || [];
  const recent = timestamps.filter(t => now - t < JOIN_RATE_WINDOW);
  if (recent.length >= JOIN_RATE_MAX) return false;
  recent.push(now);
  serverJoinRateLimit.set(userId, recent);
  return true;
}

/** INVITE_VERIFY rate limit — anti-énumération de codes d'invitation. */
export const inviteVerifyRateLimit = new Map<string, number[]>();
export const INVITE_VERIFY_WINDOW = 60000; // 60 s
export const INVITE_VERIFY_MAX = 20;       // max 20 tentatives / min / user

export function checkInviteVerifyRate(userId: string): boolean {
  const now = Date.now();
  const timestamps = inviteVerifyRateLimit.get(userId) || [];
  const recent = timestamps.filter(t => now - t < INVITE_VERIFY_WINDOW);
  if (recent.length >= INVITE_VERIFY_MAX) return false;
  recent.push(now);
  inviteVerifyRateLimit.set(userId, recent);
  return true;
}
