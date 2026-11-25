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

class BridgeClient {
  readonly #project: string;
  readonly #command: readonly [string, string];

  constructor(project: string, config: Config) {
    this.#project = project;
    this.#command = [config.python ?? "python3", config.bridge];
  }

  protected call<T>(operation: string, request: object, extra = {}): T {
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
}

export class LocalClient extends BridgeClient {
  lock(publicKey: string, profile?: string): string {
    return this.call("lock", { publicKey, profile });
  }

  lockForOwner(ownerHash160: string): string {
    return this.call("lockOwner", { ownerHash160 });
  }

  recognize(script: string, publicKey?: string): Recognition | null {
    return this.call("recognize", { script, publicKey });
  }

  #sign(options: Spend | Payment, signer: Signer): string {
    const snapshot = JSON.parse(JSON.stringify(options));
    const args = this.call<string[]>("prepare", snapshot);
    const signature = signer(...args.map((argument) => Buffer.from(argument, "hex")));
    if (!(signature instanceof Uint8Array)) throw new TypeError("Signer must return signature bytes");
    return this.call("finish", snapshot, { arguments: args, signature: Buffer.from(signature).toString("hex") });
  }

  signSpend(options: Spend, signer: Signer): string {
    return this.#sign(options, signer);
  }

  signPayment(options: Payment, signer: Signer): string {
    return this.#sign(options, signer);
  }
}

export interface Prevout extends Output {
  txid: string;
  vout: number;
}
export interface WalletRecognition extends Recognition {
  project: string;
  publicKey?: string;
  targetTemplate?: string;
  targetScriptSha256?: string;
  targetTxOutHash256?: string;
}
export type LockRequest = ({ publicKey: string; ownerHash160?: never } |
  { ownerHash160: string; publicKey?: never }) & { valueSats?: string };
export interface InputRequest {
  prevout: Prevout;
  transaction: string;
  inputIndex: number;
  sighash?: number;
  chronicleActive?: boolean;
}
export interface WalletSigningOptions {
  prevout: Prevout;
  publicKey: string;
  sighash?: number;
  chronicleActive?: boolean;
  compressOtda?: boolean;
  signerIdentifier?: string;
  historyPath?: string;
  signMessage?: boolean;
}
export interface WalletPayment extends WalletSigningOptions {
  outputs: Output[];
  feeSats: string;
}
export type WalletInput = InputRequest & WalletSigningOptions;
export interface SigningRequest {
  algorithm: string;
  payloadKind: "digest" | "message";
  signatureFormat: string;
  sighash: number;
  payload: Uint8Array;
  userId?: Uint8Array;
}
export type WalletSigner = (request: SigningRequest) => Uint8Array;
export type AsyncWalletSigner = (request: SigningRequest) => Promise<Uint8Array>;

export class WalletClient extends BridgeClient {
  readonly #template?: string;

  constructor(project: string, config: Config & { template?: string }) {
    super(project, config);
    this.#template = config.template;
  }

  prevoutFromFunding(funding: string, vout: number): Prevout {
    return this.call("prevoutFromFunding", { funding, vout });
  }

  createLock(request: LockRequest): string {
    return this.call("createLock", { ...request, template: this.#template });
  }

  recognize(request: { script: string; publicKey?: string; valueSats?: string }): WalletRecognition | null {
    return this.call("recognizeLock", request);
  }

  #prepare(request: WalletInput | WalletPayment) {
    const snapshot = JSON.parse(JSON.stringify(request));
    const { arguments: args, ...metadata } =
      this.call<Omit<SigningRequest, "payload" | "userId"> & { arguments: string[] }>("prepareWallet", snapshot);
    const [payload, userId] = args.map((value) => Buffer.from(value, "hex"));
    return { snapshot, args, request: { ...metadata, payload, userId } };
  }

  #finish(snapshot: WalletInput | WalletPayment, args: string[], signature: Uint8Array): string {
    if (!(signature instanceof Uint8Array)) throw new TypeError("Signer must return signature bytes");
    return this.call("finishWallet", snapshot, { arguments: args, signature: Buffer.from(signature).toString("hex") });
  }

  signPayment(request: WalletPayment, signer: WalletSigner): string {
    const prepared = this.#prepare(request);
    return this.#finish(prepared.snapshot, prepared.args, signer(prepared.request));
  }

  signInput(request: WalletInput, signer: WalletSigner): string {
    const prepared = this.#prepare(request);
    return this.#finish(prepared.snapshot, prepared.args, signer(prepared.request));
  }

  async signPaymentAsync(request: WalletPayment, signer: AsyncWalletSigner): Promise<string> {
    const prepared = this.#prepare(request);
    return this.#finish(prepared.snapshot, prepared.args, await signer(prepared.request));
  }

  async signInputAsync(request: WalletInput, signer: AsyncWalletSigner): Promise<string> {
    const prepared = this.#prepare(request);
    return this.#finish(prepared.snapshot, prepared.args, await signer(prepared.request));
  }

  activate(request: InputRequest): string {
    return this.call("activate", request);
  }
}
