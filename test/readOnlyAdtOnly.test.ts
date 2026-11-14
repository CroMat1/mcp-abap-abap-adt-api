// N-ABAP-1 (check-fx-abap-2.md, rischi residui 1-4). In sola lettura:
//  1. il client ammette richieste solo sotto /sap/bc/adt/ (piu' il logoff della libreria): niente
//     WebGUI, WebRFC, OData, echo;
//  2. varianti non ASCII, punto o spazio finale di un segmento, mangling (...) cadono comunque;
//  3. i tool con URL libero rifiutano i parametri sap-* (mandante, lingua, utente...) e ~*;
//  4. gli id di traces* e atcWorklists non risalgono con ../.
// Piu' la regressione: tutte le letture passano ancora contro il SAP finto.
// Usa solo API che esistevano a a2f8a2d, cosi' gli stessi test mostrano il fallimento di prima.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { createServer as httpServer } from "node:http";
import { Runtime } from "../src/server.js";
import { BoundedHttpClient, READ_ONLY_POSTS, requestContext } from "../src/lib/http.js";
import { LOCAL_TOOLS, READ_TOOLS } from "../src/toolPolicy.js";

const BASE = new URL("https://sap.example.invalid");
const SRC = "/sap/bc/adt/programs/programs/ztest/source/main";
const WEBGUI = "/sap/bc/gui/sap/its/webgui?~transaction=*SE38%20RS38M-PROGRAMM=ZX;DYNP_OKCODE=STRT";
const TRACE = "/sap/bc/adt/runtime/traces/abaptraces/bti1033_acd_00%2cAT000000.DAT";
/** Service binding con il link OData scelto da chi chiama (bindingDetails fa GET su quel link). */
const binding = (href: string) => ({
  releaseSupported: false, published: false, repair: false, bindingCreated: true,
  responsible: "U", masterLanguage: "EN", masterSystem: "PRD", name: "ZB", type: "SCO2",
  changedAt: "", version: "", createdAt: "", changedBy: "U", createdBy: "U", description: "", language: "EN",
  packageRef: { uri: "/sap/bc/adt/packages/zpkg", type: "DEVC/K", name: "ZPKG" },
  links: [{ href, rel: "http://www.sap.com/categories/odatav2" }],
  services: [{ name: "ZSRV", version: 1, releaseState: "", serviceDefinition: { uri: "/sap/bc/adt/ddic/srvd/sources/zsrvd", type: "SRVD/SRV", name: "ZSRVD" } }],
  binding: { type: "ODATA", version: "V2", category: 0, implementation: { name: "ZSRV" } },
});
const ODATA_LINK = "/sap/bc/adt/businessservices/odatav2/feap";
/** Messaggi dei filtri di sola lettura: un errore che li contiene e' un rifiuto, non un guasto. */
const FILTER = /read-only|ADT source URL/;

function fakeTransport() {
  const calls: { method: string; path: string }[] = [];
  const transport = ((url: URL, options: any, callback: (res: any) => void) => {
    calls.push({ method: options.method, path: url.pathname + url.search });
    const req: any = new EventEmitter();
    req.end = () =>
      setImmediate(() => {
        const res: any = new EventEmitter();
        res.statusCode = 200;
        res.statusMessage = "OK";
        res.headers = { "content-type": "text/plain", "x-csrf-token": "fixture-token" };
        res.destroy = () => {};
        callback(res);
        res.emit("data", Buffer.from("ok"));
        res.emit("end");
      });
    return req;
  }) as any;
  return { calls, transport };
}
const inContext = <T>(fn: () => Promise<T>) =>
  requestContext.run({ signal: new AbortController().signal }, fn);

async function fakeSap(extra: Record<string, string> = {}) {
  const seen: string[] = [];
  /** Percorsi che hanno ricevuto l'header Authorization (Basic dell'utente tecnico). */
  const withAuth: string[] = [];
  const server = httpServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    if (req.headers.authorization) withAuth.push(req.url!.split("?")[0]);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "text/plain", "x-csrf-token": "t" });
      res.end("ok");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const runtime = new Runtime({
    SAP_URL: `http://127.0.0.1:${(server.address() as any).port}`,
    SAP_USER: "fixture-user",
    SAP_PASSWORD: "fixture-password",
    SAP_CLIENT: "100",
    ...extra,
  });
  return {
    runtime,
    seen,
    withAuth,
    close: async () => {
      await runtime.close();
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

test("N-ABAP-1 punto 1: in sola lettura il client esce da /sap/bc/adt/ solo per il logoff", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { transport: f.transport });
  const rejected = [
    WEBGUI,
    "/sap/bc/gui/sap/its/webgui",
    "/sap/bc/webrfc?_FUNCTION=Z_ANY",
    "/sap/opu/odata/sap/ZSRV/ZFunction",
    "/sap/bc/echo",
    "/sap/public/info",
    "/sap/public/bc/icf/logoff/x",
    "/sap/bc/adtx/discovery",
    "/sap/bc/ad%74x/discovery",
    "/sap/bc/adt",
    "/sap/bc/bsp/sap/x",
    "/sap/bc/adt/runtime/traces/abaptraces/../../../../gui/sap/its/webgui",
    "/sap/bc/adt/x/%2e%2e/%2e%2e/echo",
  ];
  await inContext(async () => {
    for (const url of rejected) await assert.rejects(http.request({ url } as any), /read-only|SAP request/, url);
    // Ammessi: ADT e il logoff della libreria (AdtHTTP.js:135).
    for (const url of ["/sap/bc/adt/discovery", "/sap/bc/adt/compatibility/graph", "/sap/public/bc/icf/logoff", "/SAP/bc/adt/discovery".replace("/SAP", "/sap")])
      assert.equal((await http.request({ url } as any)).status, 200, url);
  });
  assert.deepEqual(
    f.calls.map((c) => c.path),
    ["/sap/bc/adt/discovery", "/sap/bc/adt/compatibility/graph", "/sap/public/bc/icf/logoff", "/sap/bc/adt/discovery"],
  );
});

test("N-ABAP-1 punto 1: WebGUI tramite i tool con URL libero non arriva a SAP", async () => {
  const f = await fakeSap();
  try {
    for (const [tool, args] of [
      ["objectStructure", { objectUrl: WEBGUI }],
      ["getTransportConfiguration", { url: WEBGUI }],
      ["classIncludes", { clas: WEBGUI }],
      ["objectStructure", { objectUrl: "/sap/bc/echo" }],
      ["getTransportConfiguration", { url: "/sap/bc/webrfc?_FUNCTION=Z_ANY" }],
      ["getTransportConfiguration", { url: "/sap/opu/odata/sap/ZSRV/ZFunction" }],
      ["bindingDetails", { binding: binding(WEBGUI) }],
    ] as const)
      await assert.rejects(f.runtime.invoke(tool, args as any), FILTER, `${tool} ${JSON.stringify(args)}`);
    assert.deepEqual(f.seen.filter((s) => !/^GET \/sap\/bc\/adt\//.test(s)), []);
  } finally {
    await f.close();
  }
});

test("N-ABAP-1 (a): /sap/bc/echo non riceve mai la password Basic, da nessun tool", async () => {
  const f = await fakeSap();
  try {
    for (const [tool, args] of [
      ["objectStructure", { objectUrl: "/sap/bc/echo" }],
      ["objectStructure", { objectUrl: "/sap/bc/echo/" }],
      ["objectStructure", { objectUrl: "/sap/bc/ECHO" }],
      ["objectStructure", { objectUrl: "/sap/bc/adt/../echo" }],
      ["objectStructure", { objectUrl: "/sap/bc/adt/%2e%2e/echo" }],
      ["objectStructure", { objectUrl: "/sap//bc/echo" }],
      ["getTransportConfiguration", { url: "/sap/bc/echo?x=1" }],
      ["classIncludes", { clas: "/sap/bc/echo" }],
      ["classComponents", { url: "/sap/bc/echo" }],
      ["mainPrograms", { includeUrl: "/sap/bc/echo" }],
      ["revisions", { objectUrl: "/sap/bc/echo" }],
      ["bindingDetails", { binding: binding("/sap/bc/echo") }],
      ["getObjectSource", { objectSourceUrl: "/sap/bc/echo/source/main" }],
      ["tracesHitList", { id: "../../../../echo" }],
      ["atcWorklists", { runResultId: "../../../echo" }],
    ] as const)
      await assert.rejects(f.runtime.invoke(tool, args as any), /read-only|single path segment|ADT source URL|Invalid Object URL/, `${tool} ${JSON.stringify(args)}`);
    assert.deepEqual(f.seen.filter((s) => /echo/i.test(s)), []);
    // Le credenziali sono partite solo verso ADT (qui: il login).
    assert.ok(f.withAuth.length > 0);
    for (const p of f.withAuth) assert.ok(p.startsWith("/sap/bc/adt/"), p);
  } finally {
    await f.close();
  }
});

test("N-ABAP-1 (b): getObjectSource accetta = nei nomi (class pool, include generati), codificato e no", async () => {
  const policy: any = await import("../src/toolPolicy.js");
  const ok = [
    "/sap/bc/adt/programs/includes/zcl_x=========ccdef/source/main",
    "/sap/bc/adt/programs/includes/zcl_x%3D%3D%3D%3D%3D%3D%3D%3D%3Dccdef/source/main",
    "/sap/bc/adt/programs/includes/zcl_x%3d%3d%3d%3d%3d%3d%3d%3d%3dccimp/source/main",
    "/sap/bc/adt/programs/includes/%2fbic%2fcl_trfn_x=====ccau/source/main",
    "/sap/bc/adt/programs/programs/cl_http_server_net============cp/source/main",
    "/sap/bc/adt/programs/programs/gp0abc1def2ghi3jkl4mno5pqr/source/main",
  ];
  for (const u of ok) assert.equal(policy.readOnlySourceUrlAllowed(u), true, u);
  // Text element: non servono a sph-bw-analyst (solo .../source/main), restano rifiutati.
  for (const u of ["/sap/bc/adt/textelements/programs/zx/source/symbols", "/sap/bc/adt/programs/includes/zcl_x====/source/mainx"])
    assert.equal(policy.readOnlySourceUrlAllowed(u), false, u);
  // Fino a SAP: le due forme arrivano come sono state scritte.
  const f = await fakeSap();
  try {
    for (const u of ok.slice(0, 2)) await f.runtime.invoke("getObjectSource", { objectSourceUrl: u });
    assert.ok(f.seen.some((s) => s.startsWith("GET /sap/bc/adt/programs/includes/zcl_x=========ccdef/source/main")), f.seen.join("\n"));
    assert.ok(f.seen.some((s) => s.startsWith("GET /sap/bc/adt/programs/includes/zcl_x%3D%3D%3D")), f.seen.join("\n"));
  } finally {
    await f.close();
  }
});

test("N-ABAP-1 punto 2: varianti non ASCII, punto o spazio finale e mangling rifiutati prima della rete", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { transport: f.transport });
  const variants = [
    "/sap/bc/adt/security./reentranceticket",
    "/sap/bc/adt/security%20/reentranceticket",
    "/sap/bc/adt/security%2e/reentranceticket",
    "/sap/bc/adt/security%2E/reentranceticket",
    "/sap/bc/adt/%C5%BFecurity/reentranceticket",
    "/sap/bc/adt/secur%C4%B1ty/reentranceticket",
    "/sap/bc/adt/%EF%BD%93ecurity/reentranceticket",
    "/sap/bc/adt/%E2%84%AAsecurity/reentranceticket",
    "/sap/bc/adt(bD1lbg==)/security/reentranceticket",
    "/sap/bc/adt/oo(bD1lbg==)/classes/zcl/source/main",
    "/sap/bc/adt/oo/classes/zcl(x)/source/main",
    "/sap/bc/adt/oo/classes/zcl/source/main%20",
    "/sap/bc/adt/oo/classes/zcl/source/main.",
    "/sap/bc/adt/oo/classes/zcl%3fsap-client%3d000/source/main",
    "/sap(bD1lbg==)/bc/adt/oo/classes/zcl/source/main",
  ];
  await inContext(async () => {
    for (const url of variants) await assert.rejects(http.request({ url } as any), /read-only|SAP request|encoding/, url);
  });
  assert.deepEqual(f.calls, [], "nessuna richiesta deve partire");
});

test("N-ABAP-1 punto 3: sui tool con URL libero niente sap-client, sap-language (e sap-*, ~*) nella query", async () => {
  const f = await fakeSap();
  try {
    for (const [tool, args] of [
      ["getObjectSource", { objectSourceUrl: `${SRC}?sap-client=000` }],
      ["getObjectSource", { objectSourceUrl: `${SRC}?SAP-LANGUAGE=DE` }],
      ["getObjectSource", { objectSourceUrl: `${SRC}?version=active&Sap-Client=000` }],
      ["getObjectSource", { objectSourceUrl: `${SRC}?sap%2Dclient=000` }],
      ["getObjectSource", { objectSourceUrl: `${SRC}?sap-user=X` }],
      ["objectStructure", { objectUrl: "/sap/bc/adt/oo/classes/zcl_x?sap-client=000" }],
      ["objectStructure", { objectUrl: "/sap/bc/adt/oo/classes/zcl_x?~transaction=SE38" }],
      ["classComponents", { url: "/sap/bc/adt/oo/classes/zcl_x?sap-language=DE" }],
      ["mainPrograms", { includeUrl: "/sap/bc/adt/programs/includes/zinc?sap-client=000" }],
      ["revisions", { objectUrl: "/sap/bc/adt/oo/classes/zcl_x?sap-client=000" }],
      ["classIncludes", { clas: "/sap/bc/adt/oo/classes/zcl_x?sap-client=000" }],
      ["getTransportConfiguration", { url: "/sap/bc/adt/cts/transportrequests/searchconfiguration/configurations/x?sap-client=000" }],
      ["bindingDetails", { binding: binding(`${ODATA_LINK}?sap-client=000`) }],
    ] as const)
      await assert.rejects(f.runtime.invoke(tool, args as any), FILTER, `${tool} ${JSON.stringify(args)}`);
    assert.deepEqual(f.seen.filter((s) => /sap-client=000|sap-language=de|sap-user|~transaction/i.test(s)), []);
    // Ammessi: la query normale, e il mandante che la libreria manda da se' al login (AdtHTTP.js:115-118).
    await f.runtime.invoke("getObjectSource", { objectSourceUrl: `${SRC}?version=active` });
    assert.ok(f.seen.some((s) => s.startsWith("GET /sap/bc/adt/compatibility/graph") && s.includes("sap-client=100")), f.seen.join("\n"));
    assert.ok(f.seen.some((s) => s.startsWith(`GET ${SRC}?version=active`)), f.seen.join("\n"));
  } finally {
    await f.close();
  }
});

test("N-ABAP-1 punto 4: gli id di traces* e atcWorklists non risalgono", async () => {
  const f = await fakeSap();
  try {
    for (const [tool, args] of [
      ["tracesHitList", { id: "../../atc/worklists/x" }],
      ["tracesDbAccess", { id: "../../../../gui/sap/its/webgui" }],
      ["tracesStatements", { id: "x/../../../cts/transportrequests" }],
      ["tracesHitList", { id: "%2e%2e/%2e%2e/atc/worklists/x" }],
      ["tracesHitList", { id: "x%2f..%2f..%2fatc" }],
      ["tracesHitList", { id: "/sap/bc/adt/runtime/traces/abaptraces/../../../atc/worklists/x" }],
      ["tracesHitList", { id: "x?sap-client=000" }],
      ["atcWorklists", { runResultId: "../../cts/transportrequests" }],
      ["atcWorklists", { runResultId: "x/../../../discovery" }],
      ["atcWorklists", { runResultId: "x?sap-client=000" }],
    ] as const)
      await assert.rejects(f.runtime.invoke(tool, args as any), /read-only|single path segment/, `${tool} ${JSON.stringify(args)}`);
    assert.deepEqual(
      f.seen.filter((s) => !/^GET \/sap\/bc\/adt\/compatibility\/graph/.test(s)),
      [],
      "solo il login puo' partire",
    );
    // Gli id reali passano: quello completo restituito da tracesList e quello corto.
    for (const [tool, args] of [
      ["tracesHitList", { id: TRACE }],
      ["tracesHitList", { id: "bti1033_acd_00%2cAT000000.DAT" }],
      ["tracesDbAccess", { id: TRACE }],
      ["tracesStatements", { id: TRACE }],
      ["atcWorklists", { runResultId: "0242AC1100021EDB9F8E4B5B7C6D8E9F" }],
    ] as const)
      await f.runtime.invoke(tool, args as any).catch((e: any) => assert.doesNotMatch(String(e.message), FILTER, tool));
    assert.ok(f.seen.some((s) => s.includes("/abaptraces/bti1033_acd_00%2cAT000000.DAT/hitlist")), f.seen.join("\n"));
    assert.ok(f.seen.some((s) => s.includes("/atc/worklists/0242AC1100021EDB9F8E4B5B7C6D8E9F")), f.seen.join("\n"));
  } finally {
    await f.close();
  }
});

/** Argomenti plausibili per ogni lettura (forme reali di ADT). */
const READ_ARGS: Record<string, Record<string, unknown>> = {
  login: {},
  logout: {},
  dropSession: {},
  healthcheck: {},
  readResultPage: { resultId: "00000000-0000-4000-8000-000000000000" },
  isProposalMessage: { proposal: {} },
  getObjectSource: { objectSourceUrl: SRC },
  objectStructure: { objectUrl: "/sap/bc/adt/oo/classes/%2fbic%2fcl_trfn_x" },
  classIncludes: { clas: "/sap/bc/adt/oo/classes/zcl_x" },
  classComponents: { url: "/sap/bc/adt/oo/classes/zcl_x" },
  searchObject: { query: "/BIC/*" },
  findObjectPath: { objectUrl: "/sap/bc/adt/oo/classes/zcl_x" },
  objectTypes: {},
  objectRegistrationInfo: { objectUrl: "/sap/bc/adt/oo/classes/zcl_x" },
  inactiveObjects: {},
  mainPrograms: { includeUrl: "/sap/bc/adt/programs/includes/zinc" },
  nodeContents: { parent_type: "DEVC/K", parent_name: "ZPKG" },
  revisions: { objectUrl: "/sap/bc/adt/oo/classes/zcl_x" },
  fragmentMappings: { url: SRC, type: "x", name: "y" },
  bindingDetails: { binding: binding(ODATA_LINK) },
  ddicElement: { path: "ZTAB" },
  ddicRepositoryAccess: { path: "ZTAB" },
  packageSearchHelp: { type: "applicationcomponents" },
  annotationDefinitions: {},
  syntaxCheckCode: { url: SRC, code: "report z.", mainUrl: SRC },
  syntaxCheckCdsUrl: { cdsUrl: "/sap/bc/adt/ddic/ddl/sources/zcds" },
  syntaxCheckTypes: {},
  codeCompletion: { sourceUrl: SRC, source: "report z.", line: 1, column: 1 },
  codeCompletionFull: { sourceUrl: SRC, source: "report z.", line: 1, column: 1, patternKey: "x" },
  codeCompletionElement: { sourceUrl: SRC, source: "report z.", line: 1, column: 1 },
  findDefinition: { url: SRC, source: "report z.", line: 1, startCol: 1, endCol: 2 },
  usageReferences: { url: SRC, line: 1, column: 1 },
  usageReferenceSnippets: { references: [] },
  abapDocumentation: { objectUri: "/sap/bc/adt/programs/programs/ztest", body: "report z.", line: 1, column: 1 },
  prettyPrinter: { source: "report z." },
  prettyPrinterSetting: {},
  unitTestOccurrenceMarkers: { url: SRC, source: "report z." },
  tableContents: { ddicEntityName: "T000", rowNumber: 1 },
  runQuery: { sqlQuery: "SELECT * FROM T000", rowNumber: 1 },
  adtDiscovery: {},
  adtCoreDiscovery: {},
  adtCompatibiliyGraph: {},
  featureDetails: { title: "x" },
  collectionFeatureDetails: { url: "/sap/bc/adt/x" },
  findCollectionByUrl: { url: "/sap/bc/adt/x" },
  loadTypes: {},
  feeds: {},
  dumps: {},
  transportInfo: { objSourceUrl: SRC },
  hasTransportConfig: {},
  transportConfigurations: {},
  getTransportConfiguration: { url: "/sap/bc/adt/cts/transportrequests/searchconfiguration/configurations/x" },
  userTransports: { user: "U" },
  transportsByConfig: { configUri: "/sap/bc/adt/cts/transportrequests/searchconfiguration/configurations/x" },
  transportReference: { pgmid: "R3TR", obj_wbtype: "CLAS", obj_name: "ZCL_X" },
  systemUsers: {},
  atcCustomizing: {},
  atcWorklists: { runResultId: "0242AC1100021EDB9F8E4B5B7C6D8E9F" },
  atcUsers: {},
  atcExemptProposal: { markerId: "x" },
  tracesList: {},
  tracesListRequests: {},
  tracesHitList: { id: TRACE },
  tracesDbAccess: { id: TRACE },
  tracesStatements: { id: TRACE },
  gitRepos: {},
};

test("regressione: le 66 letture, login, dropSession e logout passano i filtri contro il SAP finto", async () => {
  assert.deepEqual(Object.keys(READ_ARGS).sort(), [...READ_TOOLS].sort());
  const f = await fakeSap();
  const reached: string[] = [];
  try {
    for (const name of [...READ_TOOLS].sort()) {
      const before = f.seen.length;
      try {
        await f.runtime.invoke(name, READ_ARGS[name] as any);
      } catch (e: any) {
        const msg = String(e?.message);
        assert.doesNotMatch(msg, FILTER, `${name}: rifiuto indebito`);
        assert.doesNotMatch(msg, /Arguments do not match|must be an object/, `${name}: argomenti del test sbagliati`);
        assert.doesNotMatch(msg, /busy|interrupted/, `${name}: stato della sessione`);
      }
      if (f.seen.length > before) reached.push(name);
    }
    // Ogni lettura che parla con SAP ha mandato almeno una richiesta. Tacciono solo i tool locali e
    // i tre che leggono la discovery gia' in cache nel client (AdtClient.js:302-311, :98).
    const silent = [...READ_TOOLS].filter((n) => !reached.includes(n)).sort();
    const cached = ["featureDetails", "findCollectionByUrl", "hasTransportConfig"];
    assert.deepEqual(silent, [...LOCAL_TOOLS, ...cached].sort(), `non arrivati a SAP: ${silent}`);
    // Le POST di lettura viste in rete stanno tutte nell'elenco, e ogni GET sta sotto ADT o e' il logoff.
    for (const s of f.seen) {
      const [method, target] = s.split(" ");
      const path = target.split("?")[0];
      if (method === "POST") assert.ok(READ_ONLY_POSTS.some((p) => p.path === path), s);
      else assert.ok(path.startsWith("/sap/bc/adt/") || path === "/sap/public/bc/icf/logoff", s);
    }
    // Dopo dropSession e logout una lettura si riprende con login o relogin.
    await f.runtime.invoke("dropSession", {});
    await f.runtime.invoke("getObjectSource", { objectSourceUrl: SRC });
    await f.runtime.invoke("logout", {});
    await f.runtime.invoke("login", {});
    await f.runtime.invoke("getObjectSource", { objectSourceUrl: SRC });
  } finally {
    await f.close();
  }
});
