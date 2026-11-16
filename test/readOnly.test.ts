// Modalita' sola lettura (SAP_READ_ONLY). Nessun contatto con SAP: il server parte senza
// SAP_URL/credenziali ("scollegato") e si interroga solo initialize + tools/list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Runtime } from "../src/server.js";
import {
  DATA_READ_TOOLS,
  DESTRUCTIVE_TOOLS,
  LOCAL_TOOLS,
  READ_ONLY_EXCLUDED,
  READ_TOOLS,
  SESSION_TOOLS,
  WRITE_TOOLS,
  readOnlyMode,
  toolAnnotations,
} from "../src/toolPolicy.js";
import { READ_ONLY_POSTS } from "../src/lib/http.js";
import contracts from "../src/lib/input-contracts.json" with { type: "json" };

const frozenList = () =>
  readFileSync(new URL("../tools-readonly.txt", import.meta.url), "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .sort();

const root = fileURLToPath(new URL("..", import.meta.url));
const entry = fileURLToPath(new URL("../src/index.ts", import.meta.url));

function cleanEnv(extra: Record<string, string>) {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env))
    if (!/^SAP_/i.test(k) && v !== undefined) env[k] = v;
  return { ...env, ...extra };
}

/** initialize + tools/list via stdio, sorgenti TypeScript eseguiti con tsx. */
function probe(extra: Record<string, string>): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", entry], {
      cwd: root,
      env: cleanEnv(extra),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let buf = "";
    const send = (m: unknown) => child.stdin.write(JSON.stringify(m) + "\n");
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("timeout"));
    }, 30000);
    child.stdout.on("data", (chunk) => {
      buf += chunk;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.id === 1) {
          send({ jsonrpc: "2.0", method: "notifications/initialized" });
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
        } else if (msg.id === 2) {
          clearTimeout(timer);
          child.stdin.end();
          child.kill();
          resolve(msg.result.tools);
        }
      }
    });
    child.on("error", reject);
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "read-only-test", version: "0" },
      },
    });
  });
}

test("SAP_READ_ONLY: attivo per default, spento solo da 0 o false", () => {
  assert.equal(readOnlyMode({}), true);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: "" }), true);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: "1" }), true);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: "off" }), true);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: "0" }), false);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: "false" }), false);
  assert.equal(readOnlyMode({ SAP_READ_ONLY: " False " }), false);
});

test("classificazione coerente: distruttivi e dati sono sottoinsiemi noti", () => {
  for (const n of DESTRUCTIVE_TOOLS) assert.ok(WRITE_TOOLS.has(n), n);
  for (const n of DATA_READ_TOOLS) assert.ok(!WRITE_TOOLS.has(n), n);
  for (const n of SESSION_TOOLS) assert.ok(!WRITE_TOOLS.has(n), n);
  const all = new Set(new Runtime({ SAP_READ_ONLY: "0" }).tools.map((t) => t.definition.name));
  for (const n of [...WRITE_TOOLS, ...SESSION_TOOLS, ...DATA_READ_TOOLS])
    assert.ok(all.has(n), `nome inesistente nella classificazione: ${n}`);
  assert.equal(toolAnnotations("deleteObject").destructiveHint, true);
  assert.equal(toolAnnotations("createObject").readOnlyHint, false);
  assert.equal(toolAnnotations("getObjectSource").readOnlyHint, true);
  assert.equal(toolAnnotations("checkRepo").readOnlyHint, false);
});

test("elenco chiuso: ogni tool del catalogo sta in esattamente uno fra letture, scritture ed esclusi", () => {
  const catalog = [
    ...new Runtime({ SAP_READ_ONLY: "0" }).tools.map((t) => t.definition.name),
    "healthcheck",
    "readResultPage",
  ];
  for (const n of catalog) {
    const where = [READ_TOOLS.has(n), WRITE_TOOLS.has(n), n in READ_ONLY_EXCLUDED].filter(Boolean);
    assert.equal(where.length, 1, `tool non classificato o classificato due volte: ${n}`);
  }
  for (const n of [...READ_TOOLS, ...Object.keys(READ_ONLY_EXCLUDED)])
    assert.ok(catalog.includes(n), `nome inesistente nella classificazione: ${n}`);
  for (const n of [...SESSION_TOOLS, ...LOCAL_TOOLS, ...DATA_READ_TOOLS]) assert.ok(READ_TOOLS.has(n), n);
  // Esclusioni chieste dal red team (DIF-1, DIF-10): mai fra le letture.
  for (const n of ["checkRepo", "fixEdits", "atcCheckVariant", "reentranceTicket", "gitExternalRepoInfo", "remoteRepoInfo"]) {
    assert.ok(!READ_TOOLS.has(n), n);
    assert.ok(READ_ONLY_EXCLUDED[n], `${n} senza motivo di esclusione`);
  }
  // Fra i git* resta solo gitRepos (elenco locale, nessun remoto).
  assert.deepEqual([...READ_TOOLS].filter((n) => /^git|Repo(Info)?$/.test(n)), ["gitRepos"]);
  // READ_TOOLS e tools-readonly.txt sono lo stesso elenco.
  assert.deepEqual([...READ_TOOLS].sort(), frozenList());
});

test("elenco chiuso allineato a input-contracts.json e alle POST di lettura", () => {
  const contractNames = new Set(Object.keys(contracts));
  // I contratti coprono esattamente i tool dei handler (generati: scripts/generate-input-contracts.mjs).
  const handlerTools = new Runtime({ SAP_READ_ONLY: "0" }).tools.map((t) => t.definition.name);
  assert.deepEqual([...contractNames].sort(), [...handlerTools].sort());
  for (const n of READ_TOOLS)
    if (!["healthcheck", "readResultPage"].includes(n)) assert.ok(contractNames.has(n), `contratto mancante: ${n}`);
  // Ogni POST di lettura serve a un tool dell'elenco, e ogni voce dichiara la riga di libreria.
  for (const p of READ_ONLY_POSTS) {
    assert.ok(p.tools.length > 0 && p.tools.every((t) => READ_TOOLS.has(t)), p.path);
    assert.match(p.source, /^[a-zA-Z]+\.js:\d+ /, p.path);
    assert.match(p.path, /^\/sap\/bc\/adt\/[a-z/A-Z]+$/, p.path);
  }
  // Ogni riga citata esiste davvero nella libreria e contiene il percorso.
  for (const p of READ_ONLY_POSTS)
    for (const ref of p.source.split("; ")) {
      const [, file, line] = ref.match(/^([a-zA-Z]+\.js):(\d+)/)!;
      const text = readFileSync(new URL(`../node_modules/abap-adt-api/build/api/${file}`, import.meta.url), "utf8")
        .split(/\r?\n/)[Number(line) - 1];
      assert.ok(text.includes(`h.request(`) && text.includes(p.path), `${ref}: ${text}`);
    }
});

test("in sola lettura una scrittura e' rifiutata anche se chiamata direttamente", async () => {
  const r = new Runtime({});
  try {
    await assert.rejects(
      r.invoke("setObjectSource", { objectSourceUrl: "/sap/x", source: "x", lockHandle: "l" }),
      /read-only mode/,
    );
    await assert.rejects(r.invoke("lock", { objectUrl: "/sap/x" }), /read-only mode/);
    // Non scrittura classificata ma fuori elenco: rifiutata lo stesso, prima della validazione.
    await assert.rejects(r.invoke("reentranceTicket", {}), /read-only allowlist/);
    await assert.rejects(r.invoke("unknownFutureTool", {}), /read-only allowlist/);
  } finally {
    await r.close();
  }
});

const WRITE_NAME =
  /^(create|set|delete|activate|transport(Delete|Release|SetOwner|AddUser)|lock$|unLock|run(Class)|git(Create|Pull|Unlink)|pushRepo|stageRepo|switchRepoBranch|publish|unPublish)/;

test("stdio, default: tools/list senza scritture, uguale a tools-readonly.txt", async () => {
  const tools = await probe({});
  const names = tools.map((t) => t.name).sort();
  for (const t of tools) {
    assert.ok(!WRITE_TOOLS.has(t.name), `scrittura esposta: ${t.name}`);
    assert.ok(!WRITE_NAME.test(t.name), `nome da scrittura esposto: ${t.name}`);
    assert.equal(t.annotations?.readOnlyHint, true, t.name);
    assert.equal(t.annotations?.destructiveHint, false, t.name);
  }
  for (const n of ["login", "logout", "dropSession", "runQuery", "tableContents", "healthcheck"])
    assert.ok(names.includes(n), `${n} deve restare`);
  for (const n of DATA_READ_TOOLS)
    assert.match(tools.find((t) => t.name === n).description, /dati di produzione/);
  // Elenco chiuso: in sola lettura tools/list e' esattamente READ_TOOLS (= tools-readonly.txt).
  assert.deepEqual(names, frozenList());
  assert.deepEqual(names, [...READ_TOOLS].sort());
});

test("stdio, SAP_READ_ONLY=0: catalogo completo con le scritture annotate", async () => {
  const tools = await probe({ SAP_READ_ONLY: "0" });
  const names = new Set(tools.map((t) => t.name));
  assert.equal(tools.length, 128);
  for (const n of WRITE_TOOLS) assert.ok(names.has(n), `${n} deve esserci`);
  assert.equal(tools.find((t) => t.name === "deleteObject").annotations.destructiveHint, true);
  assert.equal(tools.find((t) => t.name === "createObject").annotations.readOnlyHint, false);
});
