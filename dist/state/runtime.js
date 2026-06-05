"use strict";
// ==========================================
// ALFYCHAT — Runtime Context (populated at startup)
// Route modules import this to access io / redis without closures.
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.runtime = void 0;
exports.runtime = {
    io: null,
    redis: null,
};
//# sourceMappingURL=runtime.js.map