/**
 * Classificazione dei tool: unico punto in cui si decide cosa legge e cosa scrive.
 *
 * Usata per:
 *  - la modalita' sola lettura (SAP_READ_ONLY, attiva per default): le scritture non
 *    vengono registrate in tools/list e Runtime.invoke le rifiuta;
 *  - le annotazioni MCP standard (readOnlyHint / destructiveHint / idempotentHint / openWorldHint);
 *  - l'invalidazione della cache di sorgenti e pagine prima di ogni mutazione.
 *
 * Direzione voluta: qui si elencano le SCRITTURE (come gia' faceva il set `mutations`
 * originale). Un tool nuovo non classificato verrebbe quindi trattato come lettura: il test
 * `test/readOnly.test.ts` blocca il caso confrontando il catalogo con un elenco congelato.
 */

/** Toccano solo la sessione HTTP/ADT, non il sistema. Restano anche in sola lettura:
 *  servono per il recupero dopo un timeout (`recoveryRequired`). */
export const SESSION_TOOLS = new Set(["login", "logout", "dropSession"]);

/** Scritture su SAP: crea, modifica, lock/unlock, attiva, cancella, trasporti, abapGit,
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

/** Cambia qualcosa (sessione compresa): la cache va invalidata prima. */
export function isMutation(name: string): boolean {
  return WRITE_TOOLS.has(name) || SESSION_TOOLS.has(name);
}

/** Scrittura su SAP: nascosta e rifiutata in sola lettura. */
export function isWriteTool(name: string): boolean {
  return WRITE_TOOLS.has(name);
}

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
  const write = isWriteTool(name);
  return {
    // Le tre di sessione non modificano il sistema: sono lette come readOnly.
    readOnlyHint: !write,
    destructiveHint: DESTRUCTIVE_TOOLS.has(name),
    idempotentHint: !isMutation(name) && name !== "reentranceTicket",
    openWorldHint: !LOCAL_TOOLS.has(name),
  };
}

export const PRODUCTION_DATA_NOTE =
  "ATTENZIONE: legge dati di produzione (contenuto applicativo, non solo metadati). ";

export function toolDescription(name: string, description: string): string {
  return DATA_READ_TOOLS.has(name) ? PRODUCTION_DATA_NOTE + description : description;
}
