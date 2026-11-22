import type { IncomingMessage, ServerResponse } from "node:http";
import { validateHeaderValue } from "../shared";

export type CrossOriginEmbedderPolicyOptions = {
  policy?: "require-corp" | "credentialless" | "unsafe-none";
};

const ALLOWED_POLICIES = new Set([
  "require-corp",
  "credentialless",
  "unsafe-none",
]);

function getHeaderValueFromOptions({
  policy = "require-corp",
}: Readonly<CrossOriginEmbedderPolicyOptions>): string {
  return validateHeaderValue({
    allowedValues: ALLOWED_POLICIES,
    value: policy,
    invalidValueMessage: (value) =>
      `Cross-Origin-Embedder-Policy does not support the ${JSON.stringify(
        value,
      )} policy`,
  });
}

function crossOriginEmbedderPolicy(
  options: Readonly<CrossOriginEmbedderPolicyOptions> = {},
) {
  const headerValue = getHeaderValueFromOptions(options);

  return function crossOriginEmbedderPolicyMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) {
    res.setHeader("Cross-Origin-Embedder-Policy", headerValue);
    next();
  };
}

export default crossOriginEmbedderPolicy;
