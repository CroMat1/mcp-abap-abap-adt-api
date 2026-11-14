/**
 * Classificazione dei tool: unico punto in cui si decide cosa legge e cosa scrive.
 *
 * Usata per:
 *  - la modalita' sola lettura (SAP_READ_ONLY, attiva per default): si registrano in tools/list
 *    SOLO i tool di READ_TOOLS, un elenco chiuso; Runtime.invoke rifiuta tutti gli altri;
 *  - le annotazioni MCP standard (readOnlyHint / destructiveHint / idempotentHint / openWorldHint);
 *  - l'invalidazione della cache di sorgenti e pagine prima di ogni mutazione.
 *
 * Direzione voluta (red team 13/11/2026, DIF-1): in sola lettura vale un elenco di LETTURE
 * ammesse, non una lista nera di scritture. Un tool nuovo non classificato resta fuori dalla
 * sola lettura finche' qualcuno non lo aggiunge a READ_TOOLS di proposito.
 * Il test `test/readOnly.test.ts` esige che ogni tool del catalogo stia in esattamente uno di
 * READ_TOOLS, WRITE_TOOLS e READ_ONLY_EXCLUDED, e che READ_TOOLS coincida con tools-readonly.txt.
 * Seconda difesa, indipendente: in sola lettura `BoundedHttpClient` (src/lib/http.ts) rifiuta
 * ogni metodo diverso da GET, salvo un elenco chiuso di POST di lettura, e anche le GET sui
 * percorsi vietati (READ_ONLY_BLOCKED_PATHS, per ora /sap/bc/adt/security).
 */
import { READ_ONLY_BLOCKED_PATHS, normalizedSapPath } from "./lib/http.js";

/** Toccano solo la sessione HTTP/ADT, non il sistema. Restano anche in sola lettura:
 *  servono per il recupero dopo un timeout (`recoveryRequired`). */
export const SESSION_TOOLS = new Set(["login", "logout", "dropSession"]);

/** Scritture su SAP (servono alle annotazioni e ai test; la sola lettura NON dipende da questo
 *  elenco ma da READ_TOOLS): crea, modifica, lock/unlock, attiva, cancella, trasporti, abapGit,
 *  esecuzione di codice (runClass, unit test, debugger), ATC, trace, service binding. */
export const WRITE_TOOLS = new Set(
  [
    // trasporti
    "createTransport",
    "setTransportsConfig",
    "createTransportsConfig",
    "transportDelete",
    "transportRelease",
    "transportSetOwner",
    "transportAddUser",
    // lock e sorgenti
    "lock",
    "unLock",
    "setObjectSource",
    // oggetti
    "deleteObject",
    "activateObjects",
    "activateByName",
    "createObject",
    "createTestInclude",
    // esecuzione di codice
    "runClass",
    "unitTestRun",
    "unitTestEvaluation",
    // impostazioni utente
    "setPrettyPrinterSetting",
    // abapGit
    "gitCreateRepo",
    "gitPullRepo",
    "gitUnlinkRepo",
    "stageRepo",
    "pushRepo",
    "switchRepoBranch",
    // service binding
    "publishServiceBinding",
    "unPublishServiceBinding",
    // debugger
    "debuggerListen",
    "debuggerDeleteListener",
    "debuggerSetBreakpoints",
    "debuggerDeleteBreakpoints",
    "debuggerAttach",
    "debuggerSaveSettings",
    "debuggerStep",
    "debuggerGoToStack",
    "debuggerSetVariableValue",
    // refactoring
    "renameExecute",
    "extractMethodExecute",
    // ATC
    "createAtcRun",
    "atcRequestExemption",
    "atcChangeContact",
    // trace
    "tracesSetParameters",
    "tracesCreateConfiguration",
    "tracesDeleteConfiguration",
    "tracesDelete",
  ],
);

/** Elenco chiuso dei tool ammessi in sola lettura (SAP_READ_ONLY). Deve coincidere con
 *  `tools-readonly.txt`. Comprende i tre di sessione e i tre risolti in locale. Le letture che
 *  fanno POST passano anche dal secondo filtro, READ_ONLY_POSTS in src/lib/http.ts. */
export const READ_TOOLS = new Set([
  // sessione e locali
  "login",
  "logout",
  "dropSession",
  "healthcheck",
  "readResultPage",
  "isProposalMessage",
  // oggetti, sorgenti, struttura
  "getObjectSource",
  "objectStructure",
  "classIncludes",
  "classComponents",
  "searchObject",
  "findObjectPath",
  "objectTypes",
  "objectRegistrationInfo",
  "inactiveObjects",
  "mainPrograms",
  "nodeContents",
  "revisions",
  "fragmentMappings",
  "bindingDetails",
  // DDIC
  "ddicElement",
  "ddicRepositoryAccess",
  "packageSearchHelp",
  "annotationDefinitions",
  // analisi del codice (nessuna persistenza: il sorgente viaggia nel corpo della POST)
  "syntaxCheckCode",
  "syntaxCheckCdsUrl",
  "syntaxCheckTypes",
  "codeCompletion",
  "codeCompletionFull",
  "codeCompletionElement",
  "findDefinition",
  "usageReferences",
  "usageReferenceSnippets",
  "abapDocumentation",
  "prettyPrinter",
  "prettyPrinterSetting",
  "unitTestOccurrenceMarkers",
  // dati (DATA_READ_TOOLS)
  "tableContents",
  "runQuery",
  // discovery
  "adtDiscovery",
  "adtCoreDiscovery",
  "adtCompatibiliyGraph",
  "featureDetails",
  "collectionFeatureDetails",
  "findCollectionByUrl",
  "loadTypes",
  // feed e dump
  "feeds",
  "dumps",
  // trasporti (letture)
  "transportInfo",
  "hasTransportConfig",
  "transportConfigurations",
  "getTransportConfiguration",
  "userTransports",
  "transportsByConfig",
  "transportReference",
  "systemUsers",
  // ATC (letture, tutte GET)
  "atcCustomizing",
  "atcWorklists",
  "atcUsers",
  "atcExemptProposal",
  // trace (letture, tutte GET)
  "tracesList",
  "tracesListRequests",
  "tracesHitList",
  "tracesDbAccess",
  "tracesStatements",
  // abapGit: solo l'elenco dei repo collegati, GET locale al sistema, nessun remoto
  "gitRepos",
]);

/** Non sono scritture classificate, ma restano fuori dalla sola lettura. Il motivo sta accanto
 *  al nome, cosi' chi rilegge l'elenco non deve ricostruirlo. */
export const READ_ONLY_EXCLUDED: Record<string, string> = {
  checkRepo:
    "POST verso repo.links[].href scelto da chi chiama (abapgit.js:231): release di trasporti, attivazioni (red team DIF-1)",
  fixEdits:
    "POST verso proposal['adtcore:uri'] scelto da chi chiama (refactor.js:56), controllato solo da una regex non ancorata (red team DIF-1)",
  atcCheckVariant:
    "POST /sap/bc/adt/atc/worklists (atc.js:211): crea una worklist ATC persistente; variant non codificato (DIF-10)",
  reentranceTicket: "restituisce in chiaro un ticket SSO dell'utente tecnico (DIF-10)",
  gitExternalRepoInfo:
    "POST /sap/bc/adt/abapgit/externalrepoinfo (abapgit.js:71) con URL libero: SAP apre connessioni in uscita (DIF-10)",
  remoteRepoInfo:
    "POST /sap/bc/adt/abapgit/externalrepoinfo (abapgit.js:279) con URL libero: SAP apre connessioni in uscita (DIF-10)",
  debuggerListeners:
    "debugger: senza debuggerListen/debuggerAttach (scritture) non c'e' sessione da leggere",
  debuggerStackTrace:
    "debugger: POST /sap/bc/adt/debugger (debugger.js:253), lo stesso endpoint di debuggerStep e debuggerSetVariableValue",
  debuggerVariables:
    "debugger: POST /sap/bc/adt/debugger (debugger.js:278), lo stesso endpoint di debuggerStep e debuggerSetVariableValue",
  debuggerChildVariables:
    "debugger: POST /sap/bc/adt/debugger (debugger.js:266), lo stesso endpoint di debuggerStep e debuggerSetVariableValue",
  renameEvaluate:
    "refactoring: POST /sap/bc/adt/refactorings (refactor.js:173), lo stesso endpoint di renameExecute; prepara solo una scrittura",
  renamePreview:
    "refactoring: POST /sap/bc/adt/refactorings (refactor.js:409) con un trasporto nel corpo; prepara solo renameExecute",
  extractMethodEvaluate:
    "refactoring: POST /sap/bc/adt/refactorings (refactor.js:441), lo stesso endpoint di extractMethodExecute",
  extractMethodPreview:
    "refactoring: POST /sap/bc/adt/refactorings (refactor.js:452); prepara solo extractMethodExecute",
  fixProposals: "POST /sap/bc/adt/quickfixes/evaluation (refactor.js:21): serve solo a fixEdits, escluso",
  validateNewObject:
    "POST /sap/bc/adt/<validationPath> (objectcreator.js:140) con parametri liberi: serve solo a createObject",
  atcContactUri:
    "POST /sap/bc/adt/atc/items (atc.js:438), lo stesso percorso della PUT di atcChangeContact: serve solo a quella",
};

/** Sottoinsieme delle scritture che cancellano, sovrascrivono, eseguono codice o
 *  cambiano stati difficili da ripristinare (destructiveHint). */
export const DESTRUCTIVE_TOOLS = new Set([
  "deleteObject",
  "setObjectSource",
  "activateObjects",
  "activateByName",
  "renameExecute",
  "extractMethodExecute",
  "unLock",
  "transportDelete",
  "transportRelease",
  "transportSetOwner",
  "setTransportsConfig",
  "runClass",
  "debuggerSetVariableValue",
  "gitPullRepo",
  "gitUnlinkRepo",
  "pushRepo",
  "switchRepoBranch",
  "publishServiceBinding",
  "unPublishServiceBinding",
  "tracesDelete",
  "tracesDeleteConfiguration",
]);

/** Letture che restituiscono dati applicativi (non solo metadati): restano, ma la
 *  descrizione lo dichiara. */
export const DATA_READ_TOOLS = new Set(["runQuery", "tableContents"]);

/** Tool risolti in locale, senza chiamare SAP. */
export const LOCAL_TOOLS = new Set(["healthcheck", "readResultPage", "isProposalMessage"]);

/** Cambia qualcosa (sessione compresa), oppure non e' una lettura classificata: la cache va
 *  invalidata prima. */
export function isMutation(name: string): boolean {
  return !READ_TOOLS.has(name) || SESSION_TOOLS.has(name);
}

/** Scrittura su SAP classificata. */
export function isWriteTool(name: string): boolean {
  return WRITE_TOOLS.has(name);
}

/** Ammesso in sola lettura: solo i tool dell'elenco chiuso READ_TOOLS. */
export function isReadOnlyAllowed(name: string): boolean {
  return READ_TOOLS.has(name);
}

/** Forme dei sorgenti ADT, sul percorso grezzo in minuscolo (il nome dell'oggetto puo' contenere
 *  %2f, per esempio /BIC/ -> %2fbic%2f, quindi un segmento e' [a-z0-9_%$~-]+):
 *  - .../source/main: classi, interfacce, programmi, include, gruppi funzione e moduli, CDS,
 *    tabelle e strutture (le forme dell'esempio in sph-bw-inventario/SKILL.md);
 *  - /sap/bc/adt/oo/classes/<classe>/includes/<include>: gli include di classe di classIncludes. */
const SOURCE_URL_SHAPES = [
  /^\/sap\/bc\/adt\/(?:[a-z0-9_%$~-]+\/)+source\/main$/,
  /^\/sap\/bc\/adt\/oo\/classes\/[a-z0-9_%$~-]+\/includes\/[a-z]+$/,
];

/**
 * Giro 2 (check-fx-abap.md): in sola lettura `getObjectSource` accetta solo URL con la forma di un
 * sorgente ADT, non un percorso /sap/ qualsiasi. Il percorso deve essere gia' normale (nessun
 * `.`/`..`/`%2e` che URL risolverebbe), relativo, senza frammento, senza `;`, sotto
 * /sap/bc/adt/ e fuori da READ_ONLY_BLOCKED_PATHS. La query (per esempio ?version=) non conta.
 */
export function readOnlySourceUrlAllowed(raw: string): boolean {
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.startsWith("//")) return false;
  const placeholder = "https://placeholder.invalid";
  let url: URL;
  try {
    url = new URL(raw, placeholder);
  } catch {
    return false;
  }
  if (url.origin !== placeholder || url.hash || raw.includes("#")) return false;
  const rawPath = raw.split("?")[0];
  if (rawPath !== url.pathname || rawPath.includes(";")) return false;
  const n = normalizedSapPath(rawPath);
  if (n === null || !n.startsWith("/sap/bc/adt/")) return false;
  if (READ_ONLY_BLOCKED_PATHS.some((p) => n === p || n.startsWith(p + "/"))) return false;
  const lower = rawPath.toLowerCase();
  return SOURCE_URL_SHAPES.some((re) => re.test(lower));
}

/** Argomenti URL vincolati in sola lettura: tool -> argomento e controllo. */
export const READ_ONLY_URL_ARGS: Record<string, { arg: string; allowed: (raw: string) => boolean }> = {
  getObjectSource: { arg: "objectSourceUrl", allowed: readOnlySourceUrlAllowed },
};

/**
 * SAP_READ_ONLY: attivo per default. Lo spegne solo un valore esplicito "0" o "false"
 * (senza distinzione di maiuscole). Qualunque altro valore, o l'assenza, lo lascia attivo.
 */
export function readOnlyMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env.SAP_READ_ONLY ?? "").trim().toLowerCase();
  return !(v === "0" || v === "false");
}

/**
 * SAP_AUTO_RELOGIN: attivo per default, ma conta solo in sola lettura (SAP_READ_ONLY).
 * Lo spegne solo "0" o "false". Fuori dalla sola lettura il server non rifa' mai il login da solo.
 */
export function autoReloginMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env.SAP_AUTO_RELOGIN ?? "").trim().toLowerCase();
  return !(v === "0" || v === "false");
}

export function toolAnnotations(name: string) {
  return {
    // Solo l'elenco chiuso delle letture; le tre di sessione non modificano il sistema.
    readOnlyHint: READ_TOOLS.has(name),
    destructiveHint: DESTRUCTIVE_TOOLS.has(name),
    idempotentHint: !isMutation(name),
    openWorldHint: !LOCAL_TOOLS.has(name),
  };
}

export const PRODUCTION_DATA_NOTE =
  "ATTENZIONE: legge dati di produzione (contenuto applicativo, non solo metadati). ";

export function toolDescription(name: string, description: string): string {
  return DATA_READ_TOOLS.has(name) ? PRODUCTION_DATA_NOTE + description : description;
}
