"use strict";
// ==========================================
// ALFYCHAT — Validation des endpoints de server-nodes
// ==========================================
// L'endpoint HTTP d'un server-node est déclaré par le node lui-même dans son
// handshake. Le gateway s'en sert ensuite pour proxifier des requêtes AVEC un
// secret d'authentification interne : un endpoint non validé permettait donc
// (1) d'exfiltrer ce secret vers un hôte arbitraire, (2) de transformer le
// gateway en relais SSRF vers son propre réseau privé.
//
// Ce module refuse tout ce qui n'est pas une origine publique en clair, et
// dérive un secret PAR NODE pour qu'une fuite reste circonscrite à un serveur.
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateNodeEndpoint = validateNodeEndpoint;
exports.deriveNodeSecret = deriveNodeSecret;
exports.safeSecretEqual = safeSecretEqual;
const promises_1 = require("node:dns/promises");
const node_crypto_1 = require("node:crypto");
const node_net_1 = require("node:net");
const env_1 = require("../config/env");
/**
 * Adresses que le gateway ne doit jamais joindre pour le compte d'un tiers :
 * boucle locale, réseaux privés, link-local (dont 169.254.169.254 — métadonnées
 * cloud), CGNAT, multicast.
 */
function isForbiddenAddress(addr) {
    const version = (0, node_net_1.isIP)(addr);
    if (version === 4) {
        const p = addr.split('.').map(Number);
        if (p[0] === 0)
            return true; // 0.0.0.0/8
        if (p[0] === 10)
            return true; // privé
        if (p[0] === 127)
            return true; // loopback
        if (p[0] === 169 && p[1] === 254)
            return true; // link-local / métadonnées
        if (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
            return true; // privé
        if (p[0] === 192 && p[1] === 168)
            return true; // privé
        if (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
            return true; // CGNAT
        if (p[0] >= 224)
            return true; // multicast + réservé
        return false;
    }
    if (version === 6) {
        const a = addr.toLowerCase();
        if (a === '::' || a === '::1')
            return true; // non spécifié / loopback
        if (a.startsWith('fe80'))
            return true; // link-local
        if (a.startsWith('fc') || a.startsWith('fd'))
            return true; // unique-local
        if (a.startsWith('::ffff:'))
            return isForbiddenAddress(a.slice(7)); // IPv4 mappé
        return false;
    }
    // Ni IPv4 ni IPv6 → on ne sait pas, on refuse.
    return true;
}
/**
 * Valide l'endpoint déclaré par un server-node et retourne son origine
 * normalisée, ou `null` s'il doit être rejeté.
 *
 * Refuse : les schémas autres que http(s), le HTTP en clair en production, les
 * identifiants dans l'URL, tout chemin/query (le gateway concatène les siens
 * derrière), les noms internes, et tout nom qui résout vers une adresse privée
 * (protège du DNS rebinding).
 */
async function validateNodeEndpoint(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 255)
        return null;
    let url;
    try {
        url = new URL(raw);
    }
    catch {
        return null;
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:')
        return null;
    if (env_1.IS_PRODUCTION && url.protocol !== 'https:')
        return null;
    if (url.username || url.password)
        return null;
    if ((url.pathname && url.pathname !== '/') || url.search || url.hash)
        return null;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!host)
        return null;
    // En développement uniquement, un node tourne légitimement en local.
    if (!env_1.IS_PRODUCTION && (host === 'localhost' || host === '127.0.0.1' || host === '::1')) {
        return url.origin;
    }
    if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal'))
        return null;
    let addresses;
    if ((0, node_net_1.isIP)(host)) {
        addresses = [host];
    }
    else {
        try {
            addresses = (await (0, promises_1.lookup)(host, { all: true })).map((r) => r.address);
        }
        catch {
            return null;
        }
    }
    if (addresses.length === 0)
        return null;
    if (addresses.some(isForbiddenAddress))
        return null;
    return url.origin;
}
/**
 * Secret d'authentification propre à un serveur, dérivé de `INTERNAL_SECRET`.
 * Le node calcule la même valeur depuis son propre `INTERNAL_SECRET` + son
 * serverId : le gateway n'a donc plus jamais à transmettre le secret maître,
 * et la compromission d'un node ne donne pas accès aux autres services.
 */
function deriveNodeSecret(serverId) {
    return (0, node_crypto_1.createHmac)('sha256', env_1.INTERNAL_SECRET).update(`node:${serverId}`).digest('hex');
}
/** Comparaison en temps constant (utilisée côté node comme côté gateway). */
function safeSecretEqual(a, b) {
    if (!a || !b)
        return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length)
        return false;
    return (0, node_crypto_1.timingSafeEqual)(bufA, bufB);
}
//# sourceMappingURL=node-endpoint.js.map