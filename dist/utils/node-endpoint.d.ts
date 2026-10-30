/**
 * Valide l'endpoint déclaré par un server-node et retourne son origine
 * normalisée, ou `null` s'il doit être rejeté.
 *
 * Refuse : les schémas autres que http(s), le HTTP en clair en production, les
 * identifiants dans l'URL, tout chemin/query (le gateway concatène les siens
 * derrière), les noms internes, et tout nom qui résout vers une adresse privée
 * (protège du DNS rebinding).
 */
export declare function validateNodeEndpoint(raw: unknown): Promise<string | null>;
/**
 * Secret d'authentification propre à un serveur, dérivé de `INTERNAL_SECRET`.
 * Le node calcule la même valeur depuis son propre `INTERNAL_SECRET` + son
 * serverId : le gateway n'a donc plus jamais à transmettre le secret maître,
 * et la compromission d'un node ne donne pas accès aux autres services.
 */
export declare function deriveNodeSecret(serverId: string): string;
/** Comparaison en temps constant (utilisée côté node comme côté gateway). */
export declare function safeSecretEqual(a: string | undefined, b: string | undefined): boolean;
//# sourceMappingURL=node-endpoint.d.ts.map