export { ProxyGatewayClient, type ProxyGatewayClientOptions } from "./client";
// Types
export type { ApiError, SessionInfo, SessionMetadata, VerifyResult } from "./types";
// Zod schemas
export { apiErrorSchema, sessionInfoSchema, sessionMetadataSchema, verifyResultSchema } from "./types";
// Username helpers — pure, sync
export { buildProxyUsername, parseProxyUsername } from "./types";
// Configuration and verified username builder
export { buildAndVerifyProxyUsername, configureProxy, type ProxyConfig } from "./configure";
