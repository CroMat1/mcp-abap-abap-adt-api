import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { AsyncLocalStorage } from "node:async_hooks";
import type { HttpClient } from "abap-adt-api";
import { McpError, ErrorCode } from "./errors.js";
export const requestContext = new AsyncLocalStorage<{ signal: AbortSignal }>();

/** Caratteri ammessi in un segmento di percorso, dopo la decodifica e prima delle minuscole: solo
 *  ASCII. Bastano per i nomi ABAP (anche `=` dei class pool, `$` dei pacchetti locali, `/` dei
 *  namespace, che diventa un separatore) e per gli id di ADT (`bti1033_acd_00,AT000000.DAT`).
 *  Restano fuori, fra gli altri: lettere non ASCII (`ſ`, `ı`, fullwidth, segno Kelvin), spazio,
 *  `;` (parametri di segmento), parentesi (URL mangling `(bD1lbg==)`), `?`, `#`, `%`, `\`. */
const SEGMENT_CHARS = /^[A-Za-z0-9_$~=.!*+,:@-]+$/;

/**
 * Percorso SAP come lo vedrebbe ICF nel caso peggiore: decodificato fino a stabilita', in
 * minuscolo (i nodi ICF non distinguono le maiuscole) e senza slash doppi. Restituisce null se la
 * forma e' ambigua: decodifica non valida o ancora instabile dopo 5 passi, un segmento con
 * caratteri fuori da SEGMENT_CHARS (N-ABAP-1), un segmento `.` o `..`, o che finisce con `.`.
 */
export function normalizedSapPath(pathname: string): string | null {
  let decoded = pathname;
  for (let i = 0; ; i++) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return null;
    }
    if (next === decoded) break;
    if (i >= 4) return null;
    decoded = next;
  }
  const segments = decoded.split("/").filter((s) => s !== "");
  if (segments.some((s) => !SEGMENT_CHARS.test(s) || s.endsWith("."))) return null;
  return "/" + segments.join("/").toLowerCase();
}

/**
 * N-ABAP-1: in sola lettura si esce da /sap/bc/adt/ solo per i percorsi che la libreria usa da se'.
 * Login, CSRF, keepalive e dropSession usano /sap/bc/adt/compatibility/graph (AdtHTTP.js:77, :121,
 * :146) e la discovery sta sotto /sap/bc/adt/: l'unica eccezione e' il logout.
 *  - /sap/public/bc/icf/logoff: AdtHTTP.js:135 (logout), percorso esatto.
 * Tutto il resto di /sap/ (WebGUI, WebRFC, OData, echo, BSP...) viene rifiutato prima della rete.
 */
export const READ_ONLY_ROOT = "/sap/bc/adt/";
export const READ_ONLY_EXTRA_PATHS: readonly string[] = ["/sap/public/bc/icf/logoff"];

/**
 * Percorsi vietati in sola lettura anche in GET (giro 2, check-fx-abap.md). Si confrontano sul
 * percorso normalizzato da normalizedSapPath: vale il prefisso intero e tutto cio' che sta sotto.
 *  - /sap/bc/adt/security: contiene /reentranceticket, il ticket SSO dell'utente tecnico
 *    (AdtClient.js:202, tool reentranceTicket escluso), raggiungibile da ogni tool che fa GET
 *    su un URL scelto da chi chiama (getObjectSource, getTransportConfiguration, ...).
 */
export const READ_ONLY_BLOCKED_PATHS: readonly string[] = ["/sap/bc/adt/security"];

/** Vero se in sola lettura il percorso va rifiutato: forma ambigua, fuori da /sap/bc/adt/ (salvo
 *  READ_ONLY_EXTRA_PATHS) o sotto un percorso vietato. */
export function readOnlyPathBlocked(pathname: string): boolean {
  const n = normalizedSapPath(pathname);
  if (n === null) return true;
  if (!n.startsWith(READ_ONLY_ROOT) && !READ_ONLY_EXTRA_PATHS.includes(n)) return true;
  return READ_ONLY_BLOCKED_PATHS.some((p) => n === p || n.startsWith(p + "/"));
}

/** Una POST che legge soltanto: percorso esatto (niente prefissi, niente percent-encoding), le
 *  sole chiavi di query che la libreria invia (`keys`, maiuscole esatte, una volta ciascuna) e,
 *  se serve, il valore obbligato di alcune (`query`). `source` e' la riga di
 *  node_modules/abap-adt-api/build/api (abap-adt-api 8.4.3) che la invia. */
export type ReadOnlyPost = {
  path: string;
  keys: readonly string[];
  query?: Readonly<Record<string, string>>;
  tools: readonly string[];
  source: string;
};

/**
 * Elenco chiuso delle POST ammesse in sola lettura (red team 13/11/2026, DIF-1). Ogni voce
 * serve a un tool di READ_TOOLS (src/toolPolicy.ts) e nessun percorso e' condiviso con una
 * scrittura della libreria. Restano fuori, fra le altre, /sap/bc/adt/refactorings,
 * /sap/bc/adt/debugger, /sap/bc/adt/quickfixes/*, /sap/bc/adt/atc/*, /sap/bc/adt/abapgit/*,
 * /sap/bc/adt/activation e /sap/bc/adt/cts/transportrequests/*.
 */
export const READ_ONLY_POSTS: readonly ReadOnlyPost[] = [
  { path: "/sap/bc/adt/repository/nodepath", keys: ["uri"], tools: ["findObjectPath"], source: "search.js:30 findObjectPath" },
  { path: "/sap/bc/adt/docu/abap/langu", keys: ["uri", "language", "format"], tools: ["abapDocumentation"], source: "search.js:45 abapDocumentation" },
  {
    path: "/sap/bc/adt/checkruns",
    keys: ["reporters"],
    query: { reporters: "abapCheckRun" },
    tools: ["syntaxCheckCode", "syntaxCheckCdsUrl"],
    source: "syntax.js:68 syntaxCheck; cds.js:19 syntaxCheckCDS",
  },
  { path: "/sap/bc/adt/abapsource/codecompletion/proposal", keys: ["uri", "signalCompleteness"], tools: ["codeCompletion"], source: "syntax.js:76 codeCompletion" },
  { path: "/sap/bc/adt/abapsource/codecompletion/insertion", keys: ["uri", "patternKey"], tools: ["codeCompletionFull"], source: "syntax.js:90 codeCompletionFull" },
  { path: "/sap/bc/adt/abapsource/codecompletion/elementinfo", keys: ["uri"], tools: ["codeCompletionElement"], source: "syntax.js:100 codeCompletionElement" },
  { path: "/sap/bc/adt/navigation/target", keys: ["uri", "filter"], tools: ["findDefinition"], source: "syntax.js:133 findDefinition" },
  { path: "/sap/bc/adt/repository/informationsystem/usageReferences", keys: ["uri"], tools: ["usageReferences"], source: "syntax.js:156 usageReferences" },
  { path: "/sap/bc/adt/repository/informationsystem/usageSnippets", keys: [], tools: ["usageReferenceSnippets"], source: "syntax.js:219 usageReferenceSnippets" },
  // Formatta il testo inviato e lo restituisce; le impostazioni (/prettyprinter/settings, PUT) restano fuori.
  { path: "/sap/bc/adt/abapsource/prettyprinter", keys: [], tools: ["prettyPrinter"], source: "syntax.js:290 prettyPrinter" },
  {
    path: "/sap/bc/adt/repository/nodestructure",
    keys: ["parent_type", "withShortDescriptions", "parent_name", "parent_tech_name", "user_name", "rebuild_tree"],
    tools: ["nodeContents"],
    source: "nodeContents.js:75 nodeContents",
  },
  { path: "/sap/bc/adt/datapreview/ddic", keys: ["rowNumber", "ddicEntityName"], tools: ["tableContents"], source: "tablecontents.js:166 tableContents" },
  { path: "/sap/bc/adt/datapreview/freestyle", keys: ["rowNumber"], tools: ["runQuery"], source: "tablecontents.js:175 runQuery" },
  // Controllo trasporto di un oggetto (quale request lo contiene); non crea ne' modifica request.
  { path: "/sap/bc/adt/cts/transportchecks", keys: [], tools: ["transportInfo"], source: "transports.js:59 transportInfo" },
  { path: "/sap/bc/adt/abapsource/occurencemarkers", keys: ["uri"], tools: ["unitTestOccurrenceMarkers"], source: "unittest.js:161 unitTestOccurrenceMarkers" },
  { path: "/sap/bc/adt/repository/typestructure", keys: [], tools: ["loadTypes"], source: "objectcreator.js:114 loadTypes" },
];

/** Sola lettura: GET sempre (i percorsi vietati li ferma readOnlyPathBlocked); POST solo se
 *  percorso, chiavi di query e valori obbligati corrispondono a una voce di READ_ONLY_POSTS;
 *  qualunque altro metodo mai. `url` e' quello finale, con i parametri `qs` gia' applicati. */
export function readOnlyRequestAllowed(method: string, url: URL): boolean {
  if (method === "GET") return true;
  if (method !== "POST") return false;
  const keys = [...url.searchParams.keys()];
  return READ_ONLY_POSTS.some(
    (p) =>
      url.pathname === p.path &&
      keys.every((k) => p.keys.includes(k)) &&
      new Set(keys).size === keys.length &&
      Object.entries(p.query ?? {}).every(([k, v]) => url.searchParams.get(k) === v),
  );
}

type Transport = typeof httpsRequest;

export class BoundedHttpClient implements HttpClient {
  readonly readOnly: boolean;
  private readonly transport?: Transport;
  /**
   * `readOnly` vale true se non e' indicato: un client creato senza opzioni non scrive.
   * `transport` sostituisce node:http/node:https (solo per i test).
   */
  constructor(
    readonly base: URL,
    options: { readOnly?: boolean; transport?: Transport } = {},
  ) {
    this.readOnly = options.readOnly ?? true;
    this.transport = options.transport;
  }
  async request(
    options: Parameters<HttpClient["request"]>[0],
  ): Promise<Awaited<ReturnType<HttpClient["request"]>>> {
    const context = requestContext.getStore();
    if (!context)
      throw new McpError(
        ErrorCode.InternalError,
        "SAP request outside an owned operation",
      );
    context.signal.throwIfAborted();
    const url = new URL(options.url, this.base);
    let decoded = url.pathname;
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        throw new McpError(ErrorCode.InvalidParams, "Invalid SAP URL encoding");
      }
    }
    if (
      options.url.length > 8192 ||
      url.origin !== this.base.origin ||
      url.username ||
      url.password ||
      url.hash ||
      !decoded.startsWith("/sap/") ||
      decoded.includes("\\") ||
      decoded.split("/").some((s) => s === "." || s === "..")
    )
      throw new McpError(
        ErrorCode.InvalidParams,
        "SAP request must stay on the configured origin and /sap/ paths",
      );
    for (const [key, value] of Object.entries(options.qs ?? {}))
      if (value !== undefined && value !== null)
        url.searchParams.set(key, String(value));
    const method = String(options.method ?? "GET").toUpperCase();
    if (this.readOnly && readOnlyPathBlocked(url.pathname))
      throw new McpError(
        ErrorCode.InvalidParams,
        `SAP ${method} rejected: read-only mode (SAP_READ_ONLY) admits only /sap/bc/adt/ paths (plus the library logoff); this path is outside, sensitive or ambiguous`,
      );
    if (this.readOnly && !readOnlyRequestAllowed(method, url))
      throw new McpError(
        ErrorCode.InvalidParams,
        `SAP ${method} ${url.pathname} rejected: read-only mode (SAP_READ_ONLY) admits GET and a closed list of read-only POST paths`,
      );
    const body = options.body ?? "";
    if (Buffer.byteLength(body) > 2 * 1024 * 1024)
      throw new McpError(
        ErrorCode.InvalidParams,
        "SAP request body exceeds 2MiB",
      );
    const headers: Record<string, string> = {
      ...options.headers,
      "Accept-Encoding": "identity",
    };
    if (body) headers["Content-Length"] = String(Buffer.byteLength(body));
    if (options.auth)
      headers.Authorization =
        "Basic " +
        Buffer.from(
          options.auth.username + ":" + options.auth.password,
        ).toString("base64");
    return await new Promise((resolve, reject) => {
      const send =
        this.transport ??
        ((url.protocol === "https:" ? httpsRequest : httpRequest) as Transport);
      const req = send(
        url,
        {
          method,
          headers,
          signal: context.signal,
          agent: false,
          rejectUnauthorized: true,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let bytes = 0;
          const fail = (message: string) => {
            res.destroy();
            reject(new McpError(ErrorCode.InternalError, message));
          };
          if (res.statusCode! >= 300 && res.statusCode! < 400) {
            fail("SAP redirect rejected; configure the final HTTPS origin");
            return;
          }
          if (
            res.headers["content-encoding"] &&
            res.headers["content-encoding"] !== "identity"
          ) {
            fail("Compressed SAP response rejected");
            return;
          }
          if (Number(res.headers["content-length"] ?? 0) > 4 * 1024 * 1024) {
            fail("SAP response exceeds 4MiB; narrow the query");
            return;
          }
          res.on("data", (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > 4 * 1024 * 1024)
              fail("SAP response exceeds 4MiB; narrow the query");
            else chunks.push(chunk);
          });
          res.on("error", () =>
            reject(
              new McpError(
                ErrorCode.InternalError,
                "SAP response interrupted; a write may already have been applied",
              ),
            ),
          );
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            if (
              (/xml/i.test(String(res.headers["content-type"] ?? "")) ||
                /^\s*<\?xml/.test(text)) &&
              /<!DOCTYPE|<!ENTITY/i.test(text)
            ) {
              reject(
                new McpError(
                  ErrorCode.InternalError,
                  "SAP XML entity declarations rejected",
                ),
              );
              return;
            }
            const responseHeaders: Record<string, string | string[]> = {};
            for (const [key, value] of Object.entries(res.headers))
              if (value !== undefined) responseHeaders[key] = value;
            resolve({
              body: text,
              status: res.statusCode ?? 500,
              statusText: res.statusMessage ?? "",
              headers: responseHeaders,
            });
          });
        },
      );
      req.on("error", () =>
        reject(
          new McpError(
            ErrorCode.InternalError,
            context.signal.aborted
              ? "SAP operation cancelled or timed out; inspect the system before retrying a write"
              : "SAP connection failed; verify reachability and trusted CA. A write may already have been applied.",
          ),
        ),
      );
      req.end(body);
    });
  }
}
