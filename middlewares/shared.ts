export type HeaderValueValidationOptions<T extends string> = {
  allowedValues: ReadonlySet<T>;
  value: unknown;
  allowArray?: boolean;
  allowEmptyString?: boolean;
  normalize?: (value: string) => string;
  invalidValueMessage: (value: unknown) => string;
  emptyArrayMessage?: (value: unknown) => string;
  duplicateValueMessage?: (value: unknown) => string;
};

export function validateHeaderValue<T extends string>({
  allowedValues,
  value,
  allowArray = false,
  allowEmptyString = false,
  normalize = (token) => token,
  invalidValueMessage,
  emptyArrayMessage,
  duplicateValueMessage,
}: Readonly<HeaderValueValidationOptions<T>>): string {
  const values =
    typeof value === "string" ? [value] : allowArray ? value : [value];

  if (!Array.isArray(values) || (Array.isArray(value) && !allowArray)) {
    throw new Error(invalidValueMessage(value));
  }

  if (values.length === 0) {
    throw new Error(emptyArrayMessage?.(value) ?? invalidValueMessage(value));
  }

  const tokensSeen = new Set<T>();
  const tokens: T[] = [];

  for (const rawToken of values) {
    if (typeof rawToken !== "string") {
      throw new Error(invalidValueMessage(rawToken));
    }

    const token = normalize(rawToken) as T;

    if (!allowedValues.has(token) || (!allowEmptyString && rawToken === "")) {
      throw new Error(invalidValueMessage(rawToken));
    }

    if (tokensSeen.has(token)) {
      throw new Error(
        duplicateValueMessage?.(rawToken) ?? invalidValueMessage(rawToken),
      );
    }

    tokensSeen.add(token);
    tokens.push(token);
  }

  return tokens.join(",");
}
