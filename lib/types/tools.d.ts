import type { SecurityService } from './service.js';
import type { PluginContext, ToolDefinition } from './types.js';
export declare function createSecurityTools(service: SecurityService): ToolDefinition[];
export declare function registerSecurityTools(ctx: PluginContext, service: SecurityService): () => void;
