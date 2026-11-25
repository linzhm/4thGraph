export type { Config, Output, Payment, Recognition, Signer, Spend } from "../../../../shared/sdk/typescript/index.ts";
import { LocalClient, type Config } from "../../../../shared/sdk/typescript/index.ts";

export const createClient = (config: Config) => new LocalClient("lamport-ots", config);
