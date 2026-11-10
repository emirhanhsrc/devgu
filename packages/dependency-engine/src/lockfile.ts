export interface LockedPackage {
  name: string;
  version: string;
  /** Lockfile path of the entry, e.g. node_modules/a/node_modules/b. */
  location: string;
  direct: boolean;
  dev: boolean;
  /** Only registry packages can be matched against the npm advisory database. */
  registry: boolean;
}

export interface ParsedLockfile {
  lockfileVersion: number;
  packages: LockedPackage[];
}

const MAX_PACKAGES = 20_000;

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length < 300 ? value : undefined;
}

function nameFromLocation(location: string): string | undefined {
  const marker = "node_modules/";
  const index = location.lastIndexOf(marker);
  return index < 0 ? undefined : str(location.slice(index + marker.length));
}

function isRegistry(entry: Json): boolean {
  const resolved = str(entry["resolved"]);
  if (entry["link"] === true) return false;
  if (resolved === undefined) return true; // very old lockfiles omit it; version is still a registry version
  return (
    /^https?:\/\//i.test(resolved) &&
    !/\.git(#|$)/i.test(resolved) &&
    !/^https?:\/\/github\.com\//i.test(resolved)
  );
}

/**
 * Parses package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2 and 3). The input is
 * untrusted: every field is type checked and counts are bounded. Throws Error on invalid input.
 */
export function parsePackageLock(text: string): ParsedLockfile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `Lockfile is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  if (!isObject(raw)) throw new Error("Lockfile root must be an object");
  const lockfileVersion = typeof raw["lockfileVersion"] === "number" ? raw["lockfileVersion"] : 1;
  const packages: LockedPackage[] = [];

  if (isObject(raw["packages"])) {
    const entries = raw["packages"];
    const root = isObject(entries[""]) ? entries[""] : {};
    const directNames = new Set<string>();
    const devNames = new Set<string>();
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      if (isObject(root[field])) Object.keys(root[field]).forEach((n) => directNames.add(n));
    }
    if (isObject(root["devDependencies"])) {
      Object.keys(root["devDependencies"]).forEach((n) => {
        directNames.add(n);
        devNames.add(n);
      });
    }
    for (const [location, entry] of Object.entries(entries)) {
      if (location === "" || !isObject(entry)) continue;
      const version = str(entry["version"]);
      const name = str(entry["name"]) ?? nameFromLocation(location);
      if (!version || !name) continue;
      if (packages.length >= MAX_PACKAGES)
        throw new Error(`Lockfile has more than ${MAX_PACKAGES} packages`);
      const topLevel = location === `node_modules/${name}`;
      packages.push({
        name,
        version,
        location,
        direct: topLevel && directNames.has(name),
        dev: entry["dev"] === true || entry["devOptional"] === true,
        registry: isRegistry(entry),
      });
    }
  } else if (isObject(raw["dependencies"])) {
    const walk = (deps: Json, prefix: string, depth: number): void => {
      if (depth > 50) return;
      for (const [name, entry] of Object.entries(deps)) {
        if (!isObject(entry)) continue;
        const version = str(entry["version"]);
        if (version) {
          if (packages.length >= MAX_PACKAGES)
            throw new Error(`Lockfile has more than ${MAX_PACKAGES} packages`);
          packages.push({
            name,
            version,
            location: `${prefix}node_modules/${name}`,
            // v1 lockfiles do not record the root manifest, so top-level entries are treated as direct.
            direct: depth === 0,
            dev: entry["dev"] === true,
            registry: isRegistry(entry) && !/^(file|git|github|link):/i.test(version),
          });
        }
        if (isObject(entry["dependencies"]))
          walk(entry["dependencies"], `${prefix}node_modules/${name}/`, depth + 1);
      }
    };
    walk(raw["dependencies"], "", 0);
  } else {
    throw new Error("Lockfile has neither 'packages' nor 'dependencies'");
  }
  return { lockfileVersion, packages };
}

/** Maps lockfile locations (or v1 names) to the 1-based line they start on. */
export function indexLocations(text: string): Map<string, number> {
  const index = new Map<string, number>();
  text.split("\n").forEach((line, i) => {
    const match = /^\s*"((?:node_modules\/)[^"]+)"\s*:\s*\{/.exec(line);
    if (match?.[1] && !index.has(match[1])) index.set(match[1], i + 1);
  });
  return index;
}
