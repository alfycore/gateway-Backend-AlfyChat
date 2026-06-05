import express from 'express';
/**
 * Verifies the request comes from an admin user.
 * Returns the admin userId on success, null (and sends HTTP error) on failure.
 */
export declare function requireAdmin(req: express.Request, res: express.Response): Promise<string | null>;
//# sourceMappingURL=admin-guard.d.ts.map