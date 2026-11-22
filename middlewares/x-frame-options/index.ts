import type { IncomingMessage, ServerResponse } from "node:http";
import { validateHeaderValue } from "../shared";

export type XFrameOptionsOptions = {
  action?: "deny" | "sameorigin";
};

const ALLOWED_ACTIONS = new Set<"DENY" | "SAMEORIGIN">(["DENY", "SAMEORIGIN"]);

function getHeaderValueFromOptions({
  action = "sameorigin",
}: Readonly<XFrameOptionsOptions>): string {
  return validateHeaderValue({
    allowedValues: ALLOWED_ACTIONS,
    value: action,
    normalize: (value) => {
      const normalizedAction = value.toUpperCase();
      return normalizedAction === "SAME-ORIGIN"
        ? "SAMEORIGIN"
        : normalizedAction;
    },
    invalidValueMessage: (value) =>
      `X-Frame-Options received an invalid action ${JSON.stringify(value)}`,
  });
}

function xFrameOptions(options: Readonly<XFrameOptionsOptions> = {}) {
  const headerValue = getHeaderValueFromOptions(options);

  return function xFrameOptionsMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) {
    res.setHeader("X-Frame-Options", headerValue);
    next();
  };
}

export default xFrameOptions;
