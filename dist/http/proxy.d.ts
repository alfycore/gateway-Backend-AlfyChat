import express from 'express';
/** Proxy JSON HTTP request to a microservice with optional fallback URL */
export declare function proxyRequest(targetUrl: string, req: express.Request, res: express.Response, fallbackUrl?: string): Promise<void>;
/** Proxy JSON toward a self-hosted server-node (binary passthrough for images) */
export declare function proxyToNode(nodeEndpoint: string, nodePath: string, req: express.Request, res: express.Response): Promise<void>;
/** Proxy multipart/form-data to a server-node (file uploads) */
export declare function proxyToNodeMultipart(nodeEndpoint: string, nodePath: string, req: express.Request, res: express.Response): Promise<void>;
/** Proxy raw multipart to a microservice (fallback upload without node) */
export declare function proxyMultipartToService(targetUrl: string, targetPath: string, req: express.Request, res: express.Response): Promise<void>;
/** Proxy raw multipart/JSON to a media service endpoint */
export declare function proxyToMedia(targetEndpoint: string, mediaPath: string, req: express.Request, res: express.Response): Promise<void>;
//# sourceMappingURL=proxy.d.ts.map