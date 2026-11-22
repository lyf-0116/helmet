import type { IncomingMessage, ServerResponse } from "node:http";
import { validateHeaderValue } from "../shared";

export type XPermittedCrossDomainPoliciesOptions = {
  permittedPolicies?: "none" | "master-only" | "by-content-type" | "all";
};

const ALLOWED_PERMITTED_POLICIES = new Set([
  "none",
  "master-only",
  "by-content-type",
  "all",
]);

function getHeaderValueFromOptions({
  permittedPolicies = "none",
}: Readonly<XPermittedCrossDomainPoliciesOptions>): string {
  return validateHeaderValue({
    allowedValues: ALLOWED_PERMITTED_POLICIES,
    value: permittedPolicies,
    invalidValueMessage: (value) =>
      `X-Permitted-Cross-Domain-Policies does not support ${JSON.stringify(
        value,
      )}`,
  });
}

function xPermittedCrossDomainPolicies(
  options: Readonly<XPermittedCrossDomainPoliciesOptions> = {},
) {
  const headerValue = getHeaderValueFromOptions(options);

  return function xPermittedCrossDomainPoliciesMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) {
    res.setHeader("X-Permitted-Cross-Domain-Policies", headerValue);
    next();
  };
}

export default xPermittedCrossDomainPolicies;
