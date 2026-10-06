// IndexedDB cache of parsed card tables (Task 11 Step 5; Step 5 of the perf
// review moves it into the worker). The DB sits behind a backend interface
// ({ get, put, delete, clear, list?(prefix), keys? }) so the keying + wrapper
// logic is testable without IndexedDB; idbBackend() provides the real backend
// and memoryBackend() a per-page fallback (also used by Node tests).
//
// CACHE_SCHEMA_VERSION MUST be bumped whenever the table format, parser output
// or the storage layout changes: the key embeds it, so a bump naturally misses
// every older entry instead of serving a stale table shape, and the one-time
// sweep (see createCardCache) deletes the superseded entries.
// v2: every table entry has a small `meta:` sibling used for eviction.
export const CACHE_SCHEMA_VERSION = 2;

const TABLES_PREFIX = `tables:v${CACHE_SCHEMA_VERSION}:`;
const META_PREFIX = `meta:v${CACHE_SCHEMA_VERSION}:`;

export function cacheKey(record) {
  const sha = record && record.sha256 ? record.sha256 : "";
  if (sha) return `${TABLES_PREFIX}sha256:${sha}`;
  const name = record && record.name ? record.name : "unknown";
  return `${TABLES_PREFIX}name:${name}`;
}

// Eviction bookkeeping lives in a tiny sibling entry so enumerating the cache
// never deserializes the (multi-MB) tables themselves.
export function metaKey(tablesKey) {
  return META_PREFIX + tablesKey.slice(TABLES_PREFIX.length);
}

const tablesKeyOf = (key) => TABLES_PREFIX + key.slice(META_PREFIX.length);

// The exact shape generateWebTables produces: all four table keys, each an
// array of row objects (an explicit empty record is valid). Anything else is
// cache corruption (a poisoned or stale-writer entry) and must never reach the
// viewer, which would render "Empty"/"0 combos" forever.
const TABLE_KEYS = ["lte_ca", "nr_ca", "endc", "nrdc"];
// Present only for MediaTek cards (single-carrier NR rows); validated when present.
const OPTIONAL_TABLE_KEYS = ["nr_sa"];

export function isValidTablesShape(tables) {
  if (!tables || typeof tables !== "object" || Array.isArray(tables)) return false;
  for (const key of TABLE_KEYS) {
    const rows = tables[key];
    if (!Array.isArray(rows)) return false;
    for (const row of rows) {
      if (!row || typeof row !== "object" || Array.isArray(row)) return false;
    }
  }
  for (const key of OPTIONAL_TABLE_KEYS) {
    if (tables[key] === undefined) continue;
    if (!Array.isArray(tables[key])) return false;
    for (const row of tables[key]) {
      if (!row || typeof row !== "object" || Array.isArray(row)) return false;
    }
  }
  return true;
}

function rowCountOf(tables) {
  let n = 0;
  for (const key of [...TABLE_KEYS, ...OPTIONAL_TABLE_KEYS]) n += tables[key]?.length ?? 0;
  return n;
}

// maxEntries / maxRows bound the persistent cache (Clear still wipes it). Row
// count is the cheap size proxy; ~500k rows is roughly the 200 MB budget the
// review suggested. Eviction runs after every put over the `meta:` entries only
// (a few dozen small records), oldest cachedAt first.
export function createCardCache(backend, { maxEntries = 40, maxRows = 500000 } = {}) {
  const drop = async (key) => {
    try {
      await backend.delete(key);
    } catch {
      // a backend without delete (or a failing one) still counts as a miss
    }
  };
  // Once per cache instance: delete every key outside the current schema
  // (older versions, and v1-style entries that have no meta sibling and so
  // could never be evicted). Keys only — no table is deserialized.
  let swept = false;
  const sweep = async () => {
    if (swept || typeof backend.keys !== "function") return;
    swept = true;
    let keys;
    try {
      keys = await backend.keys();
    } catch {
      return;
    }
    for (const key of keys) {
      if (typeof key !== "string" || (!key.startsWith(TABLES_PREFIX) && !key.startsWith(META_PREFIX))) await drop(key);
    }
  };
  const evict = async () => {
    if (typeof backend.list !== "function") return;
    await sweep();
    let entries;
    try {
      entries = await backend.list(META_PREFIX);
    } catch {
      return;
    }
    if (!Array.isArray(entries)) return;
    entries.sort((a, b) => (a.value?.cachedAt ?? 0) - (b.value?.cachedAt ?? 0));
    let count = entries.length;
    let rows = entries.reduce((n, e) => n + (e.value?.rowCount ?? 0), 0);
    for (const entry of entries) {
      if (count <= maxEntries && rows <= maxRows) break;
      await drop(tablesKeyOf(entry.key));
      await drop(entry.key);
      count -= 1;
      rows -= entry.value?.rowCount ?? 0;
    }
  };
  return {
    async get(record) {
      try {
        const value = await backend.get(cacheKey(record));
        if (value === null || value === undefined) return null;
        if (
          !value || typeof value !== "object" || !isValidTablesShape(value.tables)
        ) {
          await drop(cacheKey(record)); // malformed entry -> miss + delete
          await drop(metaKey(cacheKey(record)));
          return null;
        }
        return value;
      } catch {
        return null; // a broken cache must never break card rendering
      }
    },
    async put(record, tables) {
      if (!isValidTablesShape(tables)) return; // never poison the cache
      try {
        const key = cacheKey(record);
        const meta = { cachedAt: Date.now(), rowCount: rowCountOf(tables) };
        await backend.put(key, {
          tables,
          recordName: record && record.name ? record.name : "",
          ...meta,
        });
        await backend.put(metaKey(key), meta);
        await evict();
      } catch {
        // quota/errors are non-fatal
      }
    },
    // Full wipe for the Clear button: every cached parse is dropped so the
    // next open re-parses from the File. Backend failures are non-fatal, and
    // a backend without clear() (older fake/custom backends) is a no-op.
    async clearAll() {
      try {
        await backend.clear();
      } catch {
        // a broken cache must never break clearing the UI
      }
    },
  };
}

export function memoryBackend() {
  const map = new Map();
  return {
    async get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async put(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
    async clear() {
      map.clear();
    },
    async list(prefix = "") {
      return [...map.entries()].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => ({ key, value }));
    },
    async keys() {
      return [...map.keys()];
    },
  };
}

export function idbBackend({ database = "rfcard-webapp", store = "tables" } = {}) {
  let dbPromise = null;
  const open = () => {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(database, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(store)) req.result.createObjectStore(store);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    return dbPromise;
  };
  return {
    async get(key) {
      const db = await open();
      return new Promise((resolve, reject) => {
        const req = db.transaction(store, "readonly").objectStore(store).get(key);
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror = () => reject(req.error);
      });
    },
    async put(key, value) {
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        tx.objectStore(store).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    },
    async delete(key) {
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        tx.objectStore(store).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    },
    async clear() {
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        tx.objectStore(store).clear();
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    },
    // { key, value } for every entry whose key starts with `prefix` (eviction
    // passes the meta prefix, so only the small meta records are read).
    async list(prefix = "") {
      const db = await open();
      return new Promise((resolve, reject) => {
        const out = [];
        const range = prefix ? IDBKeyRange.bound(prefix, `${prefix}￿`) : undefined;
        const req = db.transaction(store, "readonly").objectStore(store).openCursor(range);
        req.onsuccess = () => {
          const cursor = req.result;
          if (cursor) {
            out.push({ key: cursor.key, value: cursor.value });
            cursor.continue();
          } else {
            resolve(out);
          }
        };
        req.onerror = () => reject(req.error);
      });
    },
    // Every key, without loading values (one-time stale-schema sweep).
    async keys() {
      const db = await open();
      return new Promise((resolve, reject) => {
        const req = db.transaction(store, "readonly").objectStore(store).getAllKeys();
        req.onsuccess = () => resolve(req.result ?? []);
        req.onerror = () => reject(req.error);
      });
    },
  };
}
