import type { SecurityService } from './service.js';
import type { PluginContext, ToolDefinition } from './types.js';
import type { DeepCoordinator } from './deep-coordinator.js';
export declare function createSecurityTools(service: SecurityService, getCoordinator?: () => DeepCoordinator | undefined): ToolDefinition[];
export declare function registerSecurityTools(ctx: PluginContext, service: SecurityService, getCoordinator?: () => DeepCoordinator | undefined): () => void;
