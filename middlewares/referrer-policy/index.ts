import type { IncomingMessage, ServerResponse } from "node:http";
import { validateHeaderValue } from "../shared";

type ReferrerPolicyToken =
  | "no-referrer"
  | "no-referrer-when-downgrade"
  | "same-origin"
  | "origin"
  | "strict-origin"
  | "origin-when-cross-origin"
  | "strict-origin-when-cross-origin"
  | "unsafe-url"
  | "";

export type ReferrerPolicyOptions = {
  policy?: ReferrerPolicyToken | ReferrerPolicyToken[];
};

const ALLOWED_TOKENS = new Set<ReferrerPolicyToken>([
  "no-referrer",
  "no-referrer-when-downgrade",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
  "",
]);

function getHeaderValueFromOptions({
  policy = ["no-referrer"],
}: Readonly<ReferrerPolicyOptions>): string {
  return validateHeaderValue({
    allowedValues: ALLOWED_TOKENS,
    value: policy,
    allowArray: true,
    allowEmptyString: true,
    invalidValueMessage: (value) =>
      `Referrer-Policy received an unexpected policy token ${JSON.stringify(
        value,
      )}`,
    emptyArrayMessage: () => "Referrer-Policy received no policy tokens",
    duplicateValueMessage: (value) =>
      `Referrer-Policy received a duplicate policy token ${JSON.stringify(
        value,
      )}`,
  });
}

function referrerPolicy(options: Readonly<ReferrerPolicyOptions> = {}) {
  const headerValue = getHeaderValueFromOptions(options);

  return function referrerPolicyMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) {
    res.setHeader("Referrer-Policy", headerValue);
    next();
  };
}

export default referrerPolicy;
