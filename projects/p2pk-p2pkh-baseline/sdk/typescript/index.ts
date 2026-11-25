export type { Config, Output, Payment, Recognition, Signer, Spend } from "../../../../shared/sdk/typescript/index.ts";
import { LocalClient, type Config } from "../../../../shared/sdk/typescript/index.ts";

export const createClient = (config: Config) => new LocalClient("p2pk-p2pkh-baseline", config);
