import { onRequestOptions as __api_prompts__id__favorite_ts_onRequestOptions } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/[id]/favorite.ts"
import { onRequestPost as __api_prompts__id__favorite_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/[id]/favorite.ts"
import { onRequestPost as __api_auth_login_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/auth/login.ts"
import { onRequestOptions as __api_auth_logout_ts_onRequestOptions } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/auth/logout.ts"
import { onRequestPost as __api_auth_logout_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/auth/logout.ts"
import { onRequestPost as __api_auth_refresh_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/auth/refresh.ts"
import { onRequestPost as __api_auth_register_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/auth/register.ts"
import { onRequestGet as __api_prompts_stats_ts_onRequestGet } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/stats.ts"
import { onRequestOptions as __api_prompts_stats_ts_onRequestOptions } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/stats.ts"
import { onRequestDelete as __api_prompts__id__ts_onRequestDelete } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/[id].ts"
import { onRequestOptions as __api_prompts__id__ts_onRequestOptions } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/[id].ts"
import { onRequestPut as __api_prompts__id__ts_onRequestPut } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts/[id].ts"
import { onRequestPost as __api_generate_prompt_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/generate-prompt.ts"
import { onRequestGet as __api_prompts_ts_onRequestGet } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts.ts"
import { onRequestOptions as __api_prompts_ts_onRequestOptions } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts.ts"
import { onRequestPost as __api_prompts_ts_onRequestPost } from "/Users/gregld/Documents/GitHub/prompt-builder/functions/api/prompts.ts"

export const routes = [
    {
      routePath: "/api/prompts/:id/favorite",
      mountPath: "/api/prompts/:id",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_prompts__id__favorite_ts_onRequestOptions],
    },
  {
      routePath: "/api/prompts/:id/favorite",
      mountPath: "/api/prompts/:id",
      method: "POST",
      middlewares: [],
      modules: [__api_prompts__id__favorite_ts_onRequestPost],
    },
  {
      routePath: "/api/auth/login",
      mountPath: "/api/auth",
      method: "POST",
      middlewares: [],
      modules: [__api_auth_login_ts_onRequestPost],
    },
  {
      routePath: "/api/auth/logout",
      mountPath: "/api/auth",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_auth_logout_ts_onRequestOptions],
    },
  {
      routePath: "/api/auth/logout",
      mountPath: "/api/auth",
      method: "POST",
      middlewares: [],
      modules: [__api_auth_logout_ts_onRequestPost],
    },
  {
      routePath: "/api/auth/refresh",
      mountPath: "/api/auth",
      method: "POST",
      middlewares: [],
      modules: [__api_auth_refresh_ts_onRequestPost],
    },
  {
      routePath: "/api/auth/register",
      mountPath: "/api/auth",
      method: "POST",
      middlewares: [],
      modules: [__api_auth_register_ts_onRequestPost],
    },
  {
      routePath: "/api/prompts/stats",
      mountPath: "/api/prompts",
      method: "GET",
      middlewares: [],
      modules: [__api_prompts_stats_ts_onRequestGet],
    },
  {
      routePath: "/api/prompts/stats",
      mountPath: "/api/prompts",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_prompts_stats_ts_onRequestOptions],
    },
  {
      routePath: "/api/prompts/:id",
      mountPath: "/api/prompts",
      method: "DELETE",
      middlewares: [],
      modules: [__api_prompts__id__ts_onRequestDelete],
    },
  {
      routePath: "/api/prompts/:id",
      mountPath: "/api/prompts",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_prompts__id__ts_onRequestOptions],
    },
  {
      routePath: "/api/prompts/:id",
      mountPath: "/api/prompts",
      method: "PUT",
      middlewares: [],
      modules: [__api_prompts__id__ts_onRequestPut],
    },
  {
      routePath: "/api/generate-prompt",
      mountPath: "/api",
      method: "POST",
      middlewares: [],
      modules: [__api_generate_prompt_ts_onRequestPost],
    },
  {
      routePath: "/api/prompts",
      mountPath: "/api",
      method: "GET",
      middlewares: [],
      modules: [__api_prompts_ts_onRequestGet],
    },
  {
      routePath: "/api/prompts",
      mountPath: "/api",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_prompts_ts_onRequestOptions],
    },
  {
      routePath: "/api/prompts",
      mountPath: "/api",
      method: "POST",
      middlewares: [],
      modules: [__api_prompts_ts_onRequestPost],
    },
  ]