// What "Fix everything" may do on its own. Shared by the engine and the app so both say the same thing.
//
// Only changes that are the person's own settings, need no admin password and can be undone run by
// themselves. Anything that needs admin (a password or a Yes box), touches code or accounts (repos,
// pull requests, GitHub settings, cloud keys), blocks ports other programs use, or stops other
// software goes on an optional list that is off until the person ticks it.
import type { Finding } from "./types";

const TOUCHES_OTHERS = /^(gh\.|deps\.|code\.|gcp\.|aws\.|win\.fw-block$|win\.startup-disable$|win\.service$|mac\.admin$)/;

export type OptionalWhy = "password" | "code" | "other-software";

/** Why a fix waits on the optional list, or null when "Fix everything" can do it by itself. */
export function optionalWhy(f: Finding): OptionalWhy | null {
  const fx = f.fix;
  if (!fx) return null;
  if (fx.admin) return "password";
  if (fx.pr || /^(gh\.|deps\.|code\.|gcp\.|aws\.)/.test(fx.fixer)) return "code";
  if (TOUCHES_OTHERS.test(fx.fixer)) return "other-software";
  return null;
}

export const OPTIONAL_SAYS: Record<OptionalWhy, string> = {
  password: "Needs your password",
  code: "Changes your code or accounts",
  "other-software": "Affects other programs",
};
