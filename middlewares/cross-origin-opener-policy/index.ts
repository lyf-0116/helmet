import type { IncomingMessage, ServerResponse } from "node:http";
import { validateHeaderValue } from "../shared";

export type CrossOriginOpenerPolicyOptions = {
  policy?:
    | "same-origin"
    | "same-origin-allow-popups"
    | "noopener-allow-popups"
    | "unsafe-none";
};

const ALLOWED_POLICIES = new Set([
  "same-origin",
  "same-origin-allow-popups",
  "noopener-allow-popups",
  "unsafe-none",
]);

function getHeaderValueFromOptions({
  policy = "same-origin",
}: Readonly<CrossOriginOpenerPolicyOptions>): string {
  return validateHeaderValue({
    allowedValues: ALLOWED_POLICIES,
    value: policy,
    invalidValueMessage: (value) =>
      `Cross-Origin-Opener-Policy does not support the ${JSON.stringify(
        value,
      )} policy`,
  });
}

function crossOriginOpenerPolicy(
  options: Readonly<CrossOriginOpenerPolicyOptions> = {},
) {
  const headerValue = getHeaderValueFromOptions(options);

  return function crossOriginOpenerPolicyMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) {
    res.setHeader("Cross-Origin-Opener-Policy", headerValue);
    next();
  };
}

export default crossOriginOpenerPolicy;
