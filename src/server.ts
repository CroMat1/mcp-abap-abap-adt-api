import { CompatibleAdtClient } from "./lib/adt-client.js";
import { McpServer } from "@modelcontextprotocol/server";
import { ADTClient, isLoginError, session_types } from "abap-adt-api";
import { z } from "zod";
import { createHandlers } from "./handlers/registry.js";
import { SourceCache } from "./lib/sourceCache.js";
import { ResultPages, textResult } from "./lib/results.js";
import { BoundedHttpClient, requestContext } from "./lib/http.js";
import { ErrorCode, McpError, safeError } from "./lib/errors.js";
import { toolSchema } from "./schema.js";
import {
  FREE_URL_ARGS,
  LOCAL_TOOLS,
  PATH_ID_ARGS,
  READ_ONLY_URL_ARGS,
  argStrings,
  readOnlyQueryAllowed,
  SESSION_TOOLS,
  autoReloginMode,
  isMutation,
  isReadOnlyAllowed,
  readOnlyMode,
  toolAnnotations,
  toolDescription,
} from "./toolPolicy.js";
function argumentSecrets(args: unknown): string[] {
  const found: string[] = [];
  const visit = (value: unknown) => {
    if (value && typeof value === "object")
      for (const [key, child] of Object.entries(value)) {
        if (
          /password|token|authorization/i.test(key) &&
          typeof child === "string" &&
          child
        ) {
          found.push(
            child,
            Buffer.from(child).toString("base64"),
            encodeURIComponent(child),
          );
        } else visit(child);
      }
  };
  visit(args);
  return found;
}
/** Sessione SAP scaduta o CSRF non piu' valido: AdtCsrfException oppure HTTP 401. */
export function isSessionExpired(error: unknown): boolean {
  try {
    return !!error && typeof error === "object" && isLoginError(error as any);
  } catch {
    return false;
  }
}
/** Evento sintetico su stderr (stdout e' il canale MCP). Mai credenziali: solo nome del tool ed esito. */
export type SessionEvent = {
  event: "sap_session_relogin";
  tool: string;
  outcome: "retry_ok" | "relogin_failed" | "retry_failed";
};
const stderrSessionLog = (e: SessionEvent) => {
  process.stderr.write(
    JSON.stringify({ level: "warn", service: "mcp-abap-abap-adt-api", ...e }) +
      "\n",
  );
};
export class Runtime {
  readonly cache = new SourceCache();
  readonly pages = new ResultPages();
  readonly handlers;
  readonly tools;
  readonly client?: ADTClient;
  readonly secrets: string[];
  readonly timeoutMs: number;
  /** SAP_READ_ONLY (attiva per default): le scritture non sono registrate ne' eseguibili. */
  readonly readOnly: boolean;
  /** SAP_AUTO_RELOGIN (attiva per default, ha effetto solo in sola lettura): vedi invoke. */
  readonly autoRelogin: boolean;
  /** Destinazione degli eventi di sessione; sostituibile nei test. */
  sessionLog: (e: SessionEvent) => void = stderrSessionLog;
  private reloginPromise?: Promise<void>;
  private active?: { abort: AbortController; done: Promise<unknown> };
  private closing = false;
  private recoveryRequired = false;
  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.secrets = [env.SAP_PASSWORD ?? "", env.SAP_BEARER_TOKEN ?? ""];
    this.readOnly = readOnlyMode(env);
    this.autoRelogin = this.readOnly && autoReloginMode(env);
    this.timeoutMs = Number(env.SAP_REQUEST_TIMEOUT_MS ?? 60000);
    if (
      !Number.isInteger(this.timeoutMs) ||
      this.timeoutMs < 100 ||
      this.timeoutMs > 120000
    )
      throw new Error("SAP_REQUEST_TIMEOUT_MS must be 100..120000");
    if (
      env.SAP_URL &&
      env.SAP_USER &&
      (env.SAP_PASSWORD || env.SAP_BEARER_TOKEN)
    ) {
      const base = new URL(env.SAP_URL);
      if (
        (base.protocol !== "https:" &&
          !(
            base.protocol === "http:" &&
            (["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) ||
              env.SAP_ALLOW_HTTP === "1")
          )) ||
        base.username ||
        base.password ||
        base.search ||
        base.hash ||
        base.pathname !== "/"
      )
        throw new Error(
          "SAP_URL must be an HTTPS origin; SAP_ALLOW_HTTP=1 explicitly permits a trusted private HTTP origin",
        );
      if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
        throw new Error(
          "TLS verification cannot be disabled; configure NODE_EXTRA_CA_CERTS",
        );
      if (env.SAP_CLIENT && !/^\d{3}$/.test(env.SAP_CLIENT))
        throw new Error("SAP_CLIENT must have three digits");
      const bearer = env.SAP_BEARER_TOKEN;
      this.client = new CompatibleAdtClient(
        new BoundedHttpClient(base, { readOnly: this.readOnly }),
        env.SAP_USER,
        bearer ? async () => bearer : env.SAP_PASSWORD!,
        env.SAP_CLIENT ?? "",
        env.SAP_LANGUAGE ?? "",
        { keepAlive: false },
      );
      this.client.stateful = session_types.stateful;
    }
    this.handlers = createHandlers(this.client, this.cache);
    this.tools = this.handlers.flatMap((handler) =>
      handler
        .getTools()
        .map((definition) => ({
          definition,
          handler,
          validation: toolSchema(definition),
        })),
    );
    if (
      new Set(this.tools.map((t) => t.definition.name)).size !==
      this.tools.length
    )
      throw new Error("Duplicate tool name");
  }
  /** Tool handler pubblicati in tools/list (in sola lettura solo l'elenco chiuso READ_TOOLS). */
  get exposedTools() {
    return this.readOnly
      ? this.tools.filter((t) => isReadOnlyAllowed(t.definition.name))
      : this.tools;
  }
  /**
   * Rifa' il login con le credenziali gia' configurate. Una sola promessa condivisa: chi
   * arriva mentre un login e' in corso attende quello, non ne apre un secondo.
   * Va chiamata dentro un requestContext (BoundedHttpClient rifiuta richieste orfane).
   */
  relogin(): Promise<void> {
    const client = this.client;
    if (!client)
      return Promise.reject(
        new McpError(ErrorCode.InternalError, "SAP is not configured"),
      );
    if (!this.reloginPromise)
      this.reloginPromise = (async () => {
        try {
          client.stateful = session_types.stateful;
          await client.login();
        } finally {
          this.reloginPromise = undefined;
        }
      })();
    return this.reloginPromise;
  }
  /** Auto-relogin ammesso solo in sola lettura, per un tool che legge e parla con SAP. */
  private canRelogin(name: string): boolean {
    return (
      this.autoRelogin &&
      this.readOnly &&
      !!this.client &&
      isReadOnlyAllowed(name) &&
      !SESSION_TOOLS.has(name) &&
      !LOCAL_TOOLS.has(name)
    );
  }
  async invoke(
    name: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ) {
    if (this.closing)
      throw new McpError(ErrorCode.InternalError, "Server is closing");
    // Difesa in profondita': in sola lettura un tool fuori elenco non e' in tools/list, ma un
    // client con un catalogo vecchio potrebbe chiamarlo lo stesso.
    if (this.readOnly && !isReadOnlyAllowed(name))
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Tool '${name}' is not in the read-only allowlist and this server runs in read-only mode (SAP_READ_ONLY)`,
      );
    if (name === "healthcheck")
      return textResult({
        status: "ready",
        sapConfigured: !!this.client,
        sapConnectionVerified: false,
        sessionRecoveryRequired: this.recoveryRequired,
        readOnly: this.readOnly,
        autoRelogin: this.autoRelogin,
        tools: this.exposedTools.length + 2,
      });
    if (name === "readResultPage")
      return textResult(
        this.pages.read(
          String(args.resultId),
          Number(args.offset ?? 0),
          Number(args.maxCharacters ?? 16000),
        ),
      );
    const entry = this.tools.find((t) => t.definition.name === name);
    if (!entry) throw new McpError(ErrorCode.MethodNotFound, "Unknown tool");
    const parsed = entry.validation.schema.safeParse(args);
    if (!parsed.success)
      throw new McpError(
        ErrorCode.InvalidParams,
        "Arguments do not match the tool schema",
      );
    const prepared = entry.validation.prepare(parsed.data);
    // Giro 2: in sola lettura alcuni URL scelti da chi chiama devono avere una forma precisa
    // (getObjectSource: solo sorgenti ADT), prima di qualunque richiesta a SAP.
    const urlRule = this.readOnly ? READ_ONLY_URL_ARGS[name] : undefined;
    if (urlRule && !urlRule.allowed(String(prepared[urlRule.arg] ?? "")))
      throw new McpError(
        ErrorCode.InvalidParams,
        `${urlRule.arg} must be an ADT source URL (.../source/main or /sap/bc/adt/oo/classes/<class>/includes/<include>) in read-only mode (SAP_READ_ONLY)`,
      );
    // N-ABAP-1: sugli URL liberi niente parametri sap-* (mandante, lingua, utente) ne' ~* (ITS).
    const freeArg = this.readOnly ? FREE_URL_ARGS[name] : undefined;
    if (freeArg && !argStrings(prepared[freeArg]).every(readOnlyQueryAllowed))
      throw new McpError(
        ErrorCode.InvalidParams,
        `${freeArg} must not carry sap-* or ~* query parameters in read-only mode (SAP_READ_ONLY)`,
      );
    // N-ABAP-1: id messi nel percorso senza codifica; un solo segmento, sempre.
    const idRule = PATH_ID_ARGS[name];
    if (idRule && !idRule.allowed(String(prepared[idRule.arg] ?? "")))
      throw new McpError(
        ErrorCode.InvalidParams,
        `${idRule.arg} must be a single path segment (no '/', '..', '?', even encoded)`,
      );
    if (signal?.aborted)
      throw new McpError(
        ErrorCode.InternalError,
        "Request cancelled before SAP operation",
      );
    if (this.active)
      throw new McpError(
        429,
        "SAP session is busy; cancel or finish the active request first",
      );
    if (
      this.recoveryRequired &&
      !["login", "logout", "dropSession"].includes(name)
    )
      throw new McpError(
        ErrorCode.InternalError,
        "Previous operation was interrupted. Inspect possible writes/locks, then explicitly login or dropSession before continuing",
      );
    const abort = new AbortController();
    const cancel = () => abort.abort();
    signal?.addEventListener("abort", cancel, { once: true });
    if (signal?.aborted) cancel();
    const deadline = performance.now() + this.timeoutMs;
    const timer = setTimeout(cancel, this.timeoutMs);
    if (isMutation(name)) {
      this.cache.clear();
      this.pages.clear();
    }
    if (this.client && !["logout", "dropSession"].includes(name))
      this.client.stateful = session_types.stateful;
    const done = requestContext.run({ signal: abort.signal }, async () => {
      abort.signal.throwIfAborted();
      let result;
      try {
        result = await entry.handler.handle(name, prepared);
      } catch (error) {
        // Sola lettura: sessione o CSRF scaduti (inattivita', o dropSession chiamato da un
        // altro agente sullo stesso processo) non richiedono di ispezionare scritture o lock,
        // che qui non esistono. Un login e UN solo nuovo tentativo; altrimenti l'errore originale.
        if (
          abort.signal.aborted ||
          !this.canRelogin(name) ||
          !isSessionExpired(error)
        )
          throw error;
        try {
          await this.relogin();
        } catch {
          this.sessionLog({
            event: "sap_session_relogin",
            tool: name,
            outcome: "relogin_failed",
          });
          throw error;
        }
        abort.signal.throwIfAborted();
        try {
          result = await entry.handler.handle(name, prepared);
        } catch {
          this.sessionLog({
            event: "sap_session_relogin",
            tool: name,
            outcome: "retry_failed",
          });
          throw error;
        }
        this.sessionLog({
          event: "sap_session_relogin",
          tool: name,
          outcome: "retry_ok",
        });
      }
      if (performance.now() > deadline) abort.abort();
      abort.signal.throwIfAborted();
      if (["login", "logout", "dropSession"].includes(name))
        this.recoveryRequired = false;
      return this.pages.wrap(result);
    });
    this.active = { abort, done };
    try {
      return await done;
    } catch (error) {
      if (abort.signal.aborted) {
        this.recoveryRequired = true;
        this.cache.clear();
        this.pages.clear();
        throw new McpError(
          ErrorCode.InternalError,
          "SAP operation cancelled or timed out; inspect writes and locks before explicit session recovery",
        );
      }
      throw new McpError(
        error instanceof McpError ? error.code : ErrorCode.InternalError,
        safeError(error, [...this.secrets, ...argumentSecrets(prepared)]),
      );
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancel);
      this.active = undefined;
    }
  }
  async close() {
    this.closing = true;
    this.active?.abort.abort();
    await this.active?.done.catch(() => {});
    this.cache.clear();
    this.pages.clear();
    if (this.client?.loggedin) {
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), 2000);
      try {
        await requestContext.run({ signal: abort.signal }, () =>
          this.client!.logout(),
        );
      } catch {
      } finally {
        clearTimeout(timer);
      }
    }
  }
}
export function createServer(runtime: Runtime) {
  const server = new McpServer({
    name: "mcp-abap-abap-adt-api",
    version: "0.1.1",
  });
  const active = new Map<string | number, AbortController>();
  server.server.setNotificationHandler(
    "notifications/cancelled",
    async (notification) => {
      if (notification.params?.requestId !== undefined)
        active.get(notification.params.requestId)?.abort();
    },
  );
  const register = (name: string, description: string, schema: z.ZodType) =>
    server.registerTool(
      name,
      {
        description: toolDescription(name, description),
        inputSchema: schema,
        annotations: toolAnnotations(name),
      },
      async (args, ctx) => {
        const controller = new AbortController();
        const id = ctx.mcpReq.id;
        const cancel = () => controller.abort();
        ctx.mcpReq.signal?.addEventListener("abort", cancel, { once: true });
        if (ctx.mcpReq.signal?.aborted) cancel();
        if (id !== undefined) active.set(id, controller);
        try {
          return await runtime.invoke(
            name,
            args as Record<string, unknown>,
            controller.signal,
          );
        } catch (error) {
          return {
            ...textResult({
              error: safeError(error, runtime.secrets),
              ...(error instanceof McpError ? { code: error.code } : {}),
            }),
            isError: true,
          };
        } finally {
          ctx.mcpReq.signal?.removeEventListener("abort", cancel);
          if (id !== undefined) active.delete(id);
        }
      },
    );
  for (const t of runtime.exposedTools)
    register(t.definition.name, t.definition.description, t.validation.schema);
  register(
    "healthcheck",
    "Local runtime/configuration status; does not claim a verified SAP connection",
    z.strictObject({}),
  );
  register(
    "readResultPage",
    "Read the next page of a large previous JSON tool result; use nextOffset, expires in five minutes. No SAP request is repeated.",
    z.strictObject({
      resultId: z.uuid(),
      offset: z.int().min(0).max(4194304).optional(),
      maxCharacters: z.int().min(2).max(16000).optional(),
    }),
  );
  return server;
}
