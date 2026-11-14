// Giro 2 di fx-abap (check-fx-abap.md, DIF-10 «parziale»): il tool reentranceTicket e' escluso,
// ma l'endpoint e' una GET e getObjectSource ci arrivava con objectSourceUrl libero.
// In sola lettura:
//  - BoundedHttpClient rifiuta /sap/bc/adt/security/ prima della rete, sul percorso decodificato,
//    senza distinguere le maiuscole, resistendo a .., %2e, %2f, ; e slash doppi;
//  - getObjectSource accetta solo URL con la forma dei sorgenti ADT;
//  - le POST in elenco accettano solo le chiavi di query che la libreria invia.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { createServer as httpServer } from "node:http";
import { ADTClient } from "abap-adt-api";
import { Runtime } from "../src/server.js";
import { BoundedHttpClient, readOnlyRequestAllowed, requestContext } from "../src/lib/http.js";
import * as policy from "../src/toolPolicy.js";
// Accesso dinamico: sul codice di prima la funzione manca e fallisce solo il suo test.
const readOnlySourceUrlAllowed = (u: string): boolean => (policy as any).readOnlySourceUrlAllowed(u);

const BASE = new URL("https://sap.example.invalid");
const TICKET = "/sap/bc/adt/security/reentranceticket";

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

test("ticket SSO via getObjectSource: rifiutato, nessuna richiesta a /security arriva a SAP", async () => {
  const seen: string[] = [];
  const server = httpServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "text/plain", "x-csrf-token": "t" });
      res.end(req.url!.toLowerCase().includes("security") ? "FAKE-SSO-TICKET-0123456789" : "ok");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const r = new Runtime({
    SAP_URL: `http://127.0.0.1:${(server.address() as any).port}`,
    SAP_USER: "fixture-user",
    SAP_PASSWORD: "fixture-password",
  });
  try {
    for (const url of [TICKET, "/sap/bc/adt/Security/ReentranceTicket", "/sap/bc/adt/security/reentranceticket/source/main"])
      await assert.rejects(r.invoke("getObjectSource", { objectSourceUrl: url }), (e: any) => {
        assert.doesNotMatch(String(e.message), /FAKE-SSO/);
        return true;
      });
    await assert.rejects(r.invoke("getTransportConfiguration", { url: TICKET }), /read-only/);
    assert.deepEqual(seen.filter((s) => /security/i.test(s)), []);
  } finally {
    await r.close();
    server.closeAllConnections();
    server.close();
    await once(server, "close");
  }
});

test("client: GET su /sap/bc/adt/security/ rifiutate prima della rete, in tutte le varianti", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { transport: f.transport });
  const variants = [
    TICKET,
    "/sap/bc/adt/security",
    "/sap/bc/adt/security/",
    "/SAP/bc/adt/security/reentranceticket".replace("/SAP", "/sap"),
    "/sap/BC/ADT/Security/ReentranceTicket",
    "/sap/bc/adt//security/reentranceticket",
    "/sap/bc/adt/security//reentranceticket",
    "/sap//bc/adt/security/reentranceticket",
    "/sap/bc/adt/%73ecurity/reentranceticket",
    "/sap/bc/adt/%2573ecurity/reentranceticket",
    "/sap/bc/adt%2fsecurity%2freentranceticket",
    "/sap/bc/adt%2Fsecurity%2Freentranceticket",
    "/sap/bc/adt/x/../security/reentranceticket",
    "/sap/bc/adt/x/%2e%2e/security/reentranceticket",
    "/sap/bc/adt/x/%2E%2E/security/reentranceticket",
    "/sap/bc/adt/x/..;/security/reentranceticket",
    "/sap/bc/adt/security;x=1/reentranceticket",
    "/sap/bc/adt/security/reentranceticket;x",
    "/sap/bc/adt/oo/classes/zcl/source/main/../../../../../security/reentranceticket",
    "/sap/bc/adt/%252573ecurity/reentranceticket",
    "/sap/bc/adt/security%00/reentranceticket",
  ];
  await inContext(async () => {
    for (const url of variants)
      await assert.rejects(http.request({ url } as any), /read-only|SAP request|encoding/, url);
  });
  assert.deepEqual(f.calls, [], "nessuna richiesta deve partire");
});

test("client: le GET legittime passano ancora (anche gli oggetti con namespace /BIC/)", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { transport: f.transport });
  await inContext(async () => {
    for (const url of [
      "/sap/bc/adt/oo/classes/%2fbic%2fcl_trfn_x/source/main",
      "/sap/bc/adt/programs/includes/zinc/source/main",
      "/sap/bc/adt/repository/informationsystem/search?operation=quickSearch&query=Z*",
      "/sap/bc/adt/compatibility/graph",
      "/sap/public/bc/icf/logoff",
      "/sap/bc/adt/securityx/foo",
    ])
      assert.equal((await http.request({ url } as any)).status, 200, url);
  });
  assert.equal(f.calls.length, 6);
});

test("fuori dalla sola lettura il blocco di /security non si applica (comportamento di prima)", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { readOnly: false, transport: f.transport });
  await inContext(async () => {
    assert.equal((await http.request({ url: TICKET } as any)).status, 200);
  });
  assert.equal(f.calls.length, 1);
});

test("getObjectSource in sola lettura: solo URL con la forma dei sorgenti ADT", async () => {
  for (const ok of [
    "/sap/bc/adt/oo/classes/zcl_x/source/main",
    "/sap/bc/adt/oo/classes/%2fbic%2fcl_trfn_x/source/main",
    "/sap/bc/adt/oo/classes/%2Fbic%2Fcl_trfn_x/source/main",
    "/sap/bc/adt/oo/classes/zcl_x/includes/testclasses",
    "/sap/bc/adt/oo/classes/zcl_x/includes/implementations",
    "/sap/bc/adt/oo/interfaces/zif_x/source/main",
    "/sap/bc/adt/programs/programs/zprog/source/main",
    "/sap/bc/adt/programs/includes/zinc/source/main",
    "/sap/bc/adt/functions/groups/zfg/source/main",
    "/sap/bc/adt/functions/groups/zfg/fmodules/z_fm/source/main",
    "/sap/bc/adt/functions/groups/zfg/includes/lzfgtop/source/main",
    "/sap/bc/adt/ddic/ddl/sources/zcds/source/main",
    "/sap/bc/adt/ddic/tables/ztab/source/main",
    "/sap/bc/adt/oo/classes/zcl_x/source/main?version=active",
    "/sap/bc/adt/programs/includes/zcl_x=====cp/source/main",
  ])
    assert.equal(readOnlySourceUrlAllowed(ok), true, ok);
  for (const bad of [
    TICKET,
    "/sap/bc/adt/security/reentranceticket/source/main",
    "/sap/bc/adt/Security/x/source/main",
    "/sap/bc/adt/cts/transportrequests/searchconfiguration/configurations",
    "/sap/bc/adt/oo/classes/zcl_x",
    "/sap/bc/adt/oo/classes/zcl_x/source/main/",
    "/sap/bc/adt/oo/classes/zcl_x/source/main#x",
    "/sap/bc/adt/oo/classes/zcl_x/source/main/../../../../security/reentranceticket",
    "/sap/bc/adt/x/%2e%2e/oo/classes/zcl/source/main",
    "/sap/bc/adt/x/..;/oo/classes/zcl/source/main",
    "/sap/bc/adt/oo/classes/zcl/includes/x/y",
    "/sap/bc/adt/oo/classes/zcl/source/main;x",
    "/sap/public/bc/icf/logoff",
    "https://evil.example/sap/bc/adt/oo/classes/zcl/source/main",
    "//evil.example/sap/bc/adt/oo/classes/zcl/source/main",
    "/sap/bc/adt/oo/classes/zcl/source/main%00",
  ])
    assert.equal(readOnlySourceUrlAllowed(bad), false, bad);

  const r = new Runtime({});
  try {
    await assert.rejects(
      r.invoke("getObjectSource", { objectSourceUrl: "/sap/bc/adt/oo/classes/zcl_x" }),
      /ADT source URL/,
    );
    // Forma ammessa: arriva fino al handler (qui SAP non e' configurato, quindi l'errore e' un altro).
    await assert.rejects(
      r.invoke("getObjectSource", { objectSourceUrl: "/sap/bc/adt/oo/classes/zcl_x/source/main" }),
      (e: any) => !/ADT source URL/.test(String(e.message)),
    );
  } finally {
    await r.close();
  }
  // Fuori dalla sola lettura la forma non si controlla.
  const w = new Runtime({ SAP_READ_ONLY: "0" });
  try {
    await assert.rejects(
      w.invoke("getObjectSource", { objectSourceUrl: "/sap/bc/adt/oo/classes/zcl_x" }),
      (e: any) => !/ADT source URL/.test(String(e.message)),
    );
  } finally {
    await w.close();
  }
});

test("POST in elenco: solo le chiavi di query della libreria, una volta, con le maiuscole esatte", () => {
  const u = (p: string) => new URL(p, BASE);
  for (const p of [
    "/sap/bc/adt/repository/nodestructure?parent_type=DEVC%2FK&method=activate",
    "/sap/bc/adt/checkruns?reporters=abapCheckRun&REPORTERS=atcChecker",
    "/sap/bc/adt/checkruns?Reporters=abapCheckRun",
    "/sap/bc/adt/checkruns?reporters=abapcheckrun",
    "/sap/bc/adt/datapreview/freestyle?rowNumber=1&rowNumber=2",
    "/sap/bc/adt/datapreview/freestyle?rownumber=1",
    "/sap/bc/adt/abapsource/prettyprinter?x=1",
    "/sap/bc/adt/navigation/target?uri=a&filter=definition&sap-client=000",
  ])
    assert.equal(readOnlyRequestAllowed("POST", u(p)), false, p);
  for (const p of [
    "/sap/bc/adt/repository/nodestructure?parent_type=DEVC%2FK&withShortDescriptions=true&parent_name=ZPKG",
    "/sap/bc/adt/checkruns?reporters=abapCheckRun",
    "/sap/bc/adt/datapreview/freestyle?rowNumber=100",
    "/sap/bc/adt/abapsource/prettyprinter",
    "/sap/bc/adt/navigation/target?uri=a&filter=definition",
  ])
    assert.equal(readOnlyRequestAllowed("POST", u(p)), true, p);
});

test("tutte le POST di lettura della libreria passano con le loro chiavi di query", async () => {
  const f = fakeTransport();
  const client = new ADTClient(new BoundedHttpClient(BASE, { transport: f.transport }), "u", "p", "100", "");
  const src = "/sap/bc/adt/programs/programs/ztest/source/main";
  await inContext(async () => {
    await client.login();
    const calls: Array<() => Promise<unknown>> = [
      () => client.findObjectPath("/sap/bc/adt/programs/programs/ztest"),
      () => client.abapDocumentation("/sap/bc/adt/programs/programs/ztest", "report z.", 1, 1),
      () => client.syntaxCheck(src, src, "report z."),
      () => client.syntaxCheck("/sap/bc/adt/ddic/ddl/sources/zcds"),
      () => client.codeCompletion(src, "report z.", 1, 1),
      () => client.codeCompletionFull(src, "report z.", 1, 1, "x"),
      () => client.codeCompletionElement(src, "report z.", 1, 1),
      () => client.findDefinition(src, "report z.", 1, 1, 2),
      () => client.usageReferences(src, 1, 1),
      () => client.usageReferenceSnippets([{ objectIdentifier: "x" } as any]),
      () => client.prettyPrinter("report z."),
      () => client.nodeContents("DEVC/K", "ZPKG", "U", "ZPKG", true, [1]),
      () => client.tableContents("T000", 1),
      () => client.runQuery("SELECT * FROM t000", 1),
      () => client.transportInfo(src, "ZPKG"),
      () => client.unitTestOccurrenceMarkers(src, "report z."),
      () => client.loadTypes(),
    ];
    for (const c of calls)
      await c().catch((e: any) => {
        // Le risposte finte non sono XML valido: e' ammesso solo un errore di parsing, mai un rifiuto.
        assert.doesNotMatch(String(e?.message), /read-only/, String(e?.message));
      });
  });
  const posts = f.calls.filter((c) => c.method === "POST").map((c) => c.path.split("?")[0]);
  assert.equal(posts.length, 17, JSON.stringify(f.calls));
});
