"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashServiceKey = exports.generateServiceKey = exports.lbRegistry = exports.serviceRegistry = void 0;
// Backward-compat re-export — la logique est dans lb/registry.ts
var registry_1 = require("../lb/registry");
Object.defineProperty(exports, "serviceRegistry", { enumerable: true, get: function () { return registry_1.lbRegistry; } });
Object.defineProperty(exports, "lbRegistry", { enumerable: true, get: function () { return registry_1.lbRegistry; } });
Object.defineProperty(exports, "generateServiceKey", { enumerable: true, get: function () { return registry_1.generateServiceKey; } });
Object.defineProperty(exports, "hashServiceKey", { enumerable: true, get: function () { return registry_1.hashServiceKey; } });
//# sourceMappingURL=service-registry.js.map