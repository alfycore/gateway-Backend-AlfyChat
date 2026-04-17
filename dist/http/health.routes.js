"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerHealthRoutes = registerHealthRoutes;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const runtime_1 = require("../state/runtime");
const connections_1 = require("../state/connections");
const env_1 = require("../config/env");
function registerHealthRoutes(app) {
    // Health check
    app.get('/health', (req, res) => {
        res.json({
            status: 'ok',
            service: 'gateway',
            uptime: process.uptime(),
            connections: connections_1.connectedClients.size,
            timestamp: new Date(),
        });
    });
    app.get('/stats', (req, res) => {
        res.json({
            connections: connections_1.connectedClients.size,
            rooms: runtime_1.runtime.io.sockets.adapter.rooms.size,
        });
    });
    // Mobile socket diagnostic endpoint
    app.get('/api/socket/status', (req, res) => {
        const authHeader = req.headers.authorization;
        const token = authHeader?.replace('Bearer ', '');
        let tokenValid = false;
        let userId = null;
        if (token) {
            try {
                const decoded = jsonwebtoken_1.default.verify(token, env_1.JWT_SECRET);
                tokenValid = true;
                userId = decoded.userId;
            }
            catch { }
        }
        res.json({
            status: 'ok',
            socketIO: true,
            transports: ['websocket', 'polling'],
            tokenProvided: !!token,
            tokenValid,
            userId,
            timestamp: new Date(),
        });
    });
}
//# sourceMappingURL=health.routes.js.map