export { ProxyGatewayClient, type ProxyGatewayClientOptions } from "./client";
// Types
export type {
    ApiError,
    BuildProxyUsernameOptions,
    HTTPCloakSpec,
    SessionInfo,
    SessionMeta,
    SessionParams,
    VerifyResult,
} from "./types";
// Zod schemas
export {
    apiErrorSchema,
    sessionInfoSchema,
    sessionMetaSchema,
    sessionParamsSchema,
    verifyResultSchema,
} from "./types";
// Username helpers — pure, sync
export { buildProxyUsername, parseProxyUsername } from "./types";
// Configuration and verified username builder
export { buildAndVerifyProxyUsername, configureProxy, type ProxyConfig } from "./configure";
// Fluent proxy configuration & connection
export { ProxyConfiguration } from "./proxy_configuration";
export { ProxyClient } from "./proxy_client";
