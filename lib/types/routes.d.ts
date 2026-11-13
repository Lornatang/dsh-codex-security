import type { IncomingMessage, ServerResponse } from 'node:http';
import type { SecurityService } from './service.js';
import type { PluginContext } from './types.js';
declare function scanIdFromPath(pathname: string): string | undefined;
export declare function handleRequest(service: SecurityService, req: IncomingMessage, res: ServerResponse): Promise<void>;
export declare function bindRoutes(ctx: PluginContext, service: SecurityService): () => void;
export { scanIdFromPath };
