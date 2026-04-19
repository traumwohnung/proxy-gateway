export { ProxyGatewayClient, type ProxyGatewayClientOptions } from "./client";
// Types
export type {
    AffinityParams,
    ApiError,
    BuildProxyUsernameOptions,
    HTTPCloakSpec,
    SessionInfo,
    UsageFilter,
    UsageResponse,
    UsageRow,
    VerifyResult,
} from "./types";
// Zod schemas
export {
    affinityParamsSchema,
    apiErrorSchema,
    granularitySchema,
    sessionInfoSchema,
    usageResponseSchema,
    usageRowSchema,
    verifyResultSchema,
} from "./types";
// Username helpers — pure, sync
export { buildProxyUsername, parseProxyUsername } from "./types";
// Configuration and verified username builder
export { buildAndVerifyProxyUsername, configureProxy, type ProxyConfig } from "./configure";
