import { spawnSync } from "node:child_process";
import { Buffer } from "node:buffer";

export interface Config {
  bridge: string;
  python?: string;
}
export interface Recognition {
  template: string;
  ownerHash160?: string;
}
export type Signer = (...arguments_: Uint8Array[]) => Uint8Array;
export interface Output {
  valueSats: string;
  script: string;
}
export interface SigningOptions {
  funding: string;
  index: number;
  publicKey: string;
  sighash?: number;
  chronicleActive?: boolean;
  compressOtda?: boolean;
  signerIdentifier?: string;
}
export interface Spend extends SigningOptions {
  transaction: string;
}
export interface Payment extends SigningOptions {
  outputs: Output[];
  feeSats: string;
}

export class LocalClient {
  readonly #project: string;
  readonly #command: readonly [string, string];

  constructor(project: string, config: Config) {
    this.#project = project;
    this.#command = [config.python ?? "python3", config.bridge];
  }

  #call<T>(operation: string, request: object, extra = {}): T {
    const input = JSON.stringify({ protocol: 1, project: this.#project, operation, request, ...extra });
    const [python, bridge] = this.#command;
    const response = spawnSync(python, [bridge], {
      input, encoding: "utf8", maxBuffer: 128 * 1024 * 1024,
    });
    if (response.error) throw response.error;
    if (response.status !== 0) throw new Error(`Local SDK bridge exited with status ${response.status}`);
    const reply = JSON.parse(response.stdout);
    if (!reply.ok) throw new Error(reply.error);
    return reply.result as T;
  }

  lock(publicKey: string, profile?: string): string {
    return this.#call("lock", { publicKey, profile });
  }

  lockForOwner(ownerHash160: string): string {
    return this.#call("lockOwner", { ownerHash160 });
  }

  recognize(script: string, publicKey?: string): Recognition | null {
    return this.#call("recognize", { script, publicKey });
  }

  #sign(options: Spend | Payment, signer: Signer): string {
    const snapshot = JSON.parse(JSON.stringify(options));
    const args = this.#call<string[]>("prepare", snapshot);
    const signature = signer(...args.map((argument) => Buffer.from(argument, "hex")));
    if (!(signature instanceof Uint8Array)) throw new TypeError("Signer must return signature bytes");
    return this.#call("finish", snapshot, { arguments: args, signature: Buffer.from(signature).toString("hex") });
  }

  signSpend(options: Spend, signer: Signer): string {
    return this.#sign(options, signer);
  }

  signPayment(options: Payment, signer: Signer): string {
    return this.#sign(options, signer);
  }
}
