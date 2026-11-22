import type { IncomingMessage, ServerResponse } from "node:http";
import contentSecurityPolicy, {
  type ContentSecurityPolicyOptions,
} from "./middlewares/content-security-policy/index.js";
import crossOriginEmbedderPolicy, {
  type CrossOriginEmbedderPolicyOptions,
} from "./middlewares/cross-origin-embedder-policy/index.js";
import crossOriginOpenerPolicy, {
  type CrossOriginOpenerPolicyOptions,
} from "./middlewares/cross-origin-opener-policy/index.js";
import crossOriginResourcePolicy, {
  type CrossOriginResourcePolicyOptions,
} from "./middlewares/cross-origin-resource-policy/index.js";
import originAgentCluster from "./middlewares/origin-agent-cluster/index.js";
import referrerPolicy, {
  type ReferrerPolicyOptions,
} from "./middlewares/referrer-policy/index.js";
import strictTransportSecurity, {
  type StrictTransportSecurityOptions,
} from "./middlewares/strict-transport-security/index.js";
import xContentTypeOptions from "./middlewares/x-content-type-options/index.js";
import xDnsPrefetchControl, {
  type XDnsPrefetchControlOptions,
} from "./middlewares/x-dns-prefetch-control/index.js";
import xDownloadOptions from "./middlewares/x-download-options/index.js";
import xFrameOptions, {
  type XFrameOptionsOptions,
} from "./middlewares/x-frame-options/index.js";
import xPermittedCrossDomainPolicies, {
  type XPermittedCrossDomainPoliciesOptions,
} from "./middlewares/x-permitted-cross-domain-policies/index.js";
import xPoweredBy from "./middlewares/x-powered-by/index.js";
import xXssProtection from "./middlewares/x-xss-protection/index.js";

type EitherKey<Key1 extends PropertyKey, Key2 extends PropertyKey, Value> =
  | ({ [K in Key1]?: Value } & { [K in Key2]?: never })
  | ({ [K in Key1]?: never } & { [K in Key2]?: Value });

export type HelmetOptions = {
  contentSecurityPolicy?: ContentSecurityPolicyOptions | boolean;
  crossOriginEmbedderPolicy?: CrossOriginEmbedderPolicyOptions | boolean;
  crossOriginOpenerPolicy?: CrossOriginOpenerPolicyOptions | boolean;
  crossOriginResourcePolicy?: CrossOriginResourcePolicyOptions | boolean;
  originAgentCluster?: boolean;
  referrerPolicy?: ReferrerPolicyOptions | boolean;
} & EitherKey<
  "strictTransportSecurity",
  "hsts",
  StrictTransportSecurityOptions | boolean
> &
  EitherKey<"xContentTypeOptions", "noSniff", boolean> &
  EitherKey<
    "xDnsPrefetchControl",
    "dnsPrefetchControl",
    XDnsPrefetchControlOptions | boolean
  > &
  EitherKey<"xDownloadOptions", "ieNoOpen", boolean> &
  EitherKey<"xFrameOptions", "frameguard", XFrameOptionsOptions | boolean> &
  EitherKey<
    "xPermittedCrossDomainPolicies",
    "permittedCrossDomainPolicies",
    XPermittedCrossDomainPoliciesOptions | boolean
  > &
  EitherKey<"xPoweredBy", "hidePoweredBy", boolean> &
  EitherKey<"xXssProtection", "xssFilter", boolean>;

type MiddlewareFunction = (
  req: IncomingMessage,
  res: ServerResponse,
  next: (error?: Error) => void,
) => void;

type MiddlewareFactory<Options> = (options?: Options) => MiddlewareFunction;

interface MiddlewareDescription<Options> {
  middleware: MiddlewareFactory<Options>;
  headerName?: string;
  takesOptions?: boolean;
  enabledByDefault?: boolean;
}

function getMiddlewareFunctionsFromOption<Options>(
  option: Options | boolean | undefined,
  {
    middleware,
    headerName,
    takesOptions = true,
    enabledByDefault = true,
  }: MiddlewareDescription<Options>,
): MiddlewareFunction[] {
  switch (option) {
    case undefined:
      return enabledByDefault ? [middleware()] : [];
    case true:
      return [middleware()];
    case false:
      return [];
    default:
      if (takesOptions) {
        return [middleware(option)];
      }
      console.warn(
        `${headerName} does not take options. Remove the property to silence this warning.`,
      );
      return [middleware()];
  }
}

function getOptionValue<
  NewKey extends keyof HelmetOptions,
  LegacyKey extends keyof HelmetOptions,
>(
  options: Readonly<HelmetOptions>,
  newKey: NewKey,
  legacyKey: LegacyKey,
  headerName: string,
): HelmetOptions[NewKey] | HelmetOptions[LegacyKey] {
  if (newKey in options && legacyKey in options) {
    throw new Error(
      `${headerName} option was specified twice. Remove the \`${legacyKey}\` option to fix this error.`,
    );
  }
  return options[newKey] ?? options[legacyKey];
}

type Helmet = {
  (
    options?: Readonly<HelmetOptions>,
  ): (
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ) => void;

  // In addition to "normal" exports, we also attach everything to the default export. This improves compatibility with the many module systems out there.
  contentSecurityPolicy: typeof contentSecurityPolicy;
  crossOriginEmbedderPolicy: typeof crossOriginEmbedderPolicy;
  crossOriginOpenerPolicy: typeof crossOriginOpenerPolicy;
  crossOriginResourcePolicy: typeof crossOriginResourcePolicy;
  dnsPrefetchControl: typeof xDnsPrefetchControl;
  frameguard: typeof xFrameOptions;
  hidePoweredBy: typeof xPoweredBy;
  hsts: typeof strictTransportSecurity;
  ieNoOpen: typeof xDownloadOptions;
  noSniff: typeof xContentTypeOptions;
  originAgentCluster: typeof originAgentCluster;
  permittedCrossDomainPolicies: typeof xPermittedCrossDomainPolicies;
  referrerPolicy: typeof referrerPolicy;
  strictTransportSecurity: typeof strictTransportSecurity;
  xContentTypeOptions: typeof xContentTypeOptions;
  xDnsPrefetchControl: typeof xDnsPrefetchControl;
  xDownloadOptions: typeof xDownloadOptions;
  xFrameOptions: typeof xFrameOptions;
  xPermittedCrossDomainPolicies: typeof xPermittedCrossDomainPolicies;
  xPoweredBy: typeof xPoweredBy;
  xXssProtection: typeof xXssProtection;
  xssFilter: typeof xXssProtection;
};

function getMiddlewareFunctionsFromOptions(
  options: Readonly<HelmetOptions>,
): MiddlewareFunction[] {
  return [
    ...getMiddlewareFunctionsFromOption(options.contentSecurityPolicy, {
      middleware: contentSecurityPolicy,
    }),
    ...getMiddlewareFunctionsFromOption(options.crossOriginEmbedderPolicy, {
      middleware: crossOriginEmbedderPolicy,
      enabledByDefault: false,
    }),
    ...getMiddlewareFunctionsFromOption(options.crossOriginOpenerPolicy, {
      middleware: crossOriginOpenerPolicy,
    }),
    ...getMiddlewareFunctionsFromOption(options.crossOriginResourcePolicy, {
      middleware: crossOriginResourcePolicy,
    }),
    ...getMiddlewareFunctionsFromOption(options.originAgentCluster, {
      middleware: originAgentCluster,
      headerName: "Origin-Agent-Cluster",
      takesOptions: false,
    }),
    ...getMiddlewareFunctionsFromOption(options.referrerPolicy, {
      middleware: referrerPolicy,
    }),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "strictTransportSecurity",
        "hsts",
        "Strict-Transport-Security",
      ),
      { middleware: strictTransportSecurity },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "xContentTypeOptions",
        "noSniff",
        "X-Content-Type-Options",
      ),
      {
        middleware: xContentTypeOptions,
        headerName: "X-Content-Type-Options",
        takesOptions: false,
      },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "xDnsPrefetchControl",
        "dnsPrefetchControl",
        "X-DNS-Prefetch-Control",
      ),
      { middleware: xDnsPrefetchControl },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "xDownloadOptions",
        "ieNoOpen",
        "X-Download-Options",
      ),
      {
        middleware: xDownloadOptions,
        headerName: "X-Download-Options",
        takesOptions: false,
      },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(options, "xFrameOptions", "frameguard", "X-Frame-Options"),
      { middleware: xFrameOptions },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "xPermittedCrossDomainPolicies",
        "permittedCrossDomainPolicies",
        "X-Permitted-Cross-Domain-Policies",
      ),
      { middleware: xPermittedCrossDomainPolicies },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(options, "xPoweredBy", "hidePoweredBy", "X-Powered-By"),
      {
        middleware: xPoweredBy,
        headerName: "X-Powered-By",
        takesOptions: false,
      },
    ),
    ...getMiddlewareFunctionsFromOption(
      getOptionValue(
        options,
        "xXssProtection",
        "xssFilter",
        "X-XSS-Protection",
      ),
      {
        middleware: xXssProtection,
        headerName: "X-XSS-Protection",
        takesOptions: false,
      },
    ),
  ];
}

const helmet: Helmet = Object.assign(
  function helmet(options: Readonly<HelmetOptions> = {}) {
    // People should be able to pass an options object with no prototype,
    // so we want this optional chaining.
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (options.constructor?.name === "IncomingMessage") {
      throw new Error(
        "It appears you have done something like `app.use(helmet)`, but it should be `app.use(helmet())`.",
      );
    }

    const middlewareFunctions = getMiddlewareFunctionsFromOptions(options);

    return function helmetMiddleware(
      req: IncomingMessage,
      res: ServerResponse,
      next: (err?: unknown) => void,
    ): void {
      let middlewareIndex = 0;

      (function internalNext(err?: unknown) {
        if (err) {
          next(err);
          return;
        }

        const middlewareFunction = middlewareFunctions[middlewareIndex];
        if (middlewareFunction) {
          middlewareIndex++;
          middlewareFunction(req, res, internalNext);
        } else {
          next();
        }
      })();
    };
  },
  {
    contentSecurityPolicy,
    crossOriginEmbedderPolicy,
    crossOriginOpenerPolicy,
    crossOriginResourcePolicy,
    originAgentCluster,
    referrerPolicy,
    strictTransportSecurity,
    xContentTypeOptions,
    xDnsPrefetchControl,
    xDownloadOptions,
    xFrameOptions,
    xPermittedCrossDomainPolicies,
    xPoweredBy,
    xXssProtection,

    // Legacy aliases
    dnsPrefetchControl: xDnsPrefetchControl,
    xssFilter: xXssProtection,
    permittedCrossDomainPolicies: xPermittedCrossDomainPolicies,
    ieNoOpen: xDownloadOptions,
    noSniff: xContentTypeOptions,
    frameguard: xFrameOptions,
    hidePoweredBy: xPoweredBy,
    hsts: strictTransportSecurity,
  },
);

export default helmet;

export {
  contentSecurityPolicy,
  crossOriginEmbedderPolicy,
  crossOriginOpenerPolicy,
  crossOriginResourcePolicy,
  originAgentCluster,
  referrerPolicy,
  strictTransportSecurity,
  xContentTypeOptions,
  xDnsPrefetchControl,
  xDownloadOptions,
  xFrameOptions,
  xPoweredBy,
  xXssProtection,

  // Legacy aliases
  strictTransportSecurity as hsts,
  xContentTypeOptions as noSniff,
  xDnsPrefetchControl as dnsPrefetchControl,
  xDownloadOptions as ieNoOpen,
  xFrameOptions as frameguard,
  xPermittedCrossDomainPolicies,
  xPermittedCrossDomainPolicies as permittedCrossDomainPolicies,
  xPoweredBy as hidePoweredBy,
  xXssProtection as xssFilter,
};
