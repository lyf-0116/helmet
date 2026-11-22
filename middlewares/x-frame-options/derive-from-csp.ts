import type { ServerResponse } from "node:http";

// - "DENY" / "SAMEORIGIN": a value the legacy header can express.
// - null: an enforced `frame-ancestors` policy exists but cannot be expressed
//   in the legacy format (allow-all, or external/multiple origins), so the
//   header must be omitted rather than tightened.
// - undefined: there is no enforced `frame-ancestors` to derive from (the
//   policy is disabled, report-only, or silent), so the caller keeps the
//   historical default instead of changing anything.
export type DerivedXFrameOptions = "DENY" | "SAMEORIGIN" | null | undefined;

const getEnforcedCspHeader = (res: ServerResponse): string | null => {
  // Only the enforced policy can drive a real block. A report-only policy is an
  // observation experiment and must never be treated as if it were enforced.
  if (!res.hasHeader("Content-Security-Policy")) {
    return null;
  }

  const header = res.getHeader("Content-Security-Policy");
  if (typeof header === "string") {
    return header;
  }
  if (Array.isArray(header)) {
    return header.join(", ");
  }
  return null;
};

const getFrameAncestorsSources = (cspHeader: string): string[] | null => {
  for (const directive of cspHeader.split(";")) {
    const tokens = directive.trim().split(/\s+/).filter(Boolean);
    if (tokens[0] === "frame-ancestors") {
      return tokens.slice(1);
    }
  }
  return null;
};

const deriveFromFrameAncestors = (
  sources: ReadonlyArray<string>,
): DerivedXFrameOptions => {
  // `frame-ancestors 'none'` (and an empty source list) blocks every frame.
  if (sources.length === 0 || sources.includes("'none'")) {
    return "DENY";
  }

  // `frame-ancestors *` allows framing from anywhere, which the legacy
  // X-Frame-Options format cannot express without blocking partners, so omit it.
  if (sources.includes("*")) {
    return null;
  }

  // A single, self-only allowlist maps cleanly onto SAMEORIGIN.
  if (sources.length === 1 && sources[0] === "'self'") {
    return "SAMEORIGIN";
  }

  // Any other allowlist (one or more external origins, schemes, or anything the
  // legacy format cannot represent) cannot be expressed, so leave the header
  // off rather than emitting a stricter value that would break those partners.
  return null;
};

const deriveXFrameOptionsFromResponse = (
  res: ServerResponse,
): DerivedXFrameOptions => {
  const cspHeader = getEnforcedCspHeader(res);
  if (cspHeader === null) {
    return undefined;
  }

  const sources = getFrameAncestorsSources(cspHeader);
  return sources === null ? undefined : deriveFromFrameAncestors(sources);
};

export default deriveXFrameOptionsFromResponse;
