import { ExtendedPoint, Point, utils, verify } from "@noble/ed25519";
import base64url from "base64url";
import bs58 from "bs58";
import type { Signer } from "../index";
import { SignatureConfig, SIG_CONFIG } from "../../constants";
import type { Nep413Payload } from "../nep413";
import { nep413Digest, nep413Payload, NEP413_RECIPIENT } from "../nep413";

// Minimal interface to be compatible with NEAR wallets' NEP-413 signMessage, as exposed by
// @hot-labs/near-connect and @near-wallet-selector. Some return the key as a near-api-js PublicKey.
export type NearPublicKey = string | Uint8Array | { toString(): string };
export interface InjectedNearSignerProvider {
  // eslint-disable-next-line @typescript-eslint/no-invalid-void-type -- wallet-selector returns Promise<SignedMessage | void>
  signMessage(params: Nep413Payload): Promise<{ publicKey?: NearPublicKey; signature: string | Uint8Array } | null | undefined | void>;
}

const PROBE_MESSAGE = "Connect NEAR wallet for Arweave uploads";

export default class InjectedNearSigner implements Signer {
  public publicKey: Buffer;
  readonly ownerLength: number = SIG_CONFIG[SignatureConfig.INJECTEDNEAR].pubLength;
  readonly signatureLength: number = SIG_CONFIG[SignatureConfig.INJECTEDNEAR].sigLength;
  readonly signatureType: number = SignatureConfig.INJECTEDNEAR;
  pem?: string | Buffer;

  protected provider: InjectedNearSignerProvider;
  constructor(provider: InjectedNearSignerProvider, publicKey?: NearPublicKey) {
    this.provider = provider;
    // connectors may report "" for the key; leave it to setPublicKey() then
    if (publicKey) this.publicKey = parsePublicKey(publicKey);
  }

  /**
   * The owner is part of what gets signed, so the signing key must be known before an item
   * is created, and wallet connectors don't reliably report it (some return an empty string
   * or a function-call key). This asks the wallet to sign a probe message and keeps the key
   * that signature actually verifies against.
   */
  async setPublicKey(): Promise<void> {
    const params = { message: PROBE_MESSAGE, nonce: utils.randomBytes(32), recipient: NEP413_RECIPIENT };
    const { publicKey, signature } = await this.signMessage(params);
    if (!publicKey) throw new Error("InjectedNearSigner - wallet did not return its public key");
    const key = parsePublicKey(publicKey);
    if (!(await ed25519Verify(signature, await nep413Digest(params), key)))
      throw new Error(
        "InjectedNearSigner - wallet signature does not match its public key, or the wallet altered the payload (e.g. added a callbackUrl)",
      );
    this.publicKey = key;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!this.publicKey) throw new Error("InjectedNearSigner - call setPublicKey() before signing");
    const params = await nep413Payload(message);
    const { signature } = await this.signMessage(params);
    // e.g. the user switched accounts in the wallet since setPublicKey()
    if (!(await ed25519Verify(signature, await nep413Digest(params), this.publicKey)))
      throw new Error(
        "InjectedNearSigner - wallet signature does not verify for this data item: it used another key than the owner, or altered the payload",
      );
    return signature;
  }

  static async verify(pk: string | Buffer, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const p = typeof pk === "string" ? base64url.toBuffer(pk) : pk;
    return ed25519Verify(signature, await nep413Digest(await nep413Payload(message)), p);
  }

  private async signMessage(params: Nep413Payload): Promise<{ publicKey?: NearPublicKey; signature: Buffer }> {
    if (!this.provider.signMessage) throw new Error("Selected Wallet does not support message signing");
    // No callbackUrl: verification assumes None, so wallets that always sign one (MyNearWallet signs
    // the page URL) cannot sign type 413. @near-wallet-selector rejects a nonce that is not a Buffer.
    const signed = await this.provider.signMessage({ ...params, nonce: Buffer.from(params.nonce) });
    if (!signed?.signature) throw new Error("InjectedNearSigner - wallet returned no signature");
    return { publicKey: signed.publicKey, signature: parseSignature(signed.signature) };
  }
}

// noble throws, rather than returning false, when a key or signature is not a valid curve point.
// A small-order key (e.g. 32 zero bytes) has no private key, yet signatures "verify" under it for
// any message; no wallet can hold one, so type 413 rejects them outright.
async function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  try {
    if (ExtendedPoint.fromAffine(Point.fromHex(Buffer.from(publicKey))).isSmallOrder()) return false;
    return await verify(Buffer.from(signature), Buffer.from(message), Buffer.from(publicKey));
  } catch {
    return false;
  }
}

// NEAR keys are "ed25519:<base58>"; other key types (secp256k1, ...) cannot produce a type 413 signature
function parsePublicKey(publicKey: NearPublicKey): Buffer {
  let bytes: Buffer;
  const key = publicKey instanceof Uint8Array ? publicKey : publicKey.toString();
  if (typeof key !== "string") bytes = Buffer.from(key);
  else if (key.startsWith("ed25519:")) bytes = Buffer.from(bs58.decode(key.slice("ed25519:".length)));
  else throw new Error(`InjectedNearSigner - only ed25519 keys are supported, got ${key.split(":")[0]}`);
  if (bytes.byteLength !== 32) throw new Error(`InjectedNearSigner - public key must be 32 bytes, but was ${bytes.byteLength}`);
  return bytes;
}

// NEP-413 says base64, but wallets also return base64url, "ed25519:<base58>" or raw bytes
function parseSignature(signature: string | Uint8Array): Buffer {
  let bytes: Buffer;
  if (typeof signature !== "string") bytes = Buffer.from(signature);
  else if (signature.startsWith("ed25519:")) bytes = Buffer.from(bs58.decode(signature.slice("ed25519:".length)));
  else bytes = base64url.toBuffer(signature);
  if (bytes.byteLength !== 64) throw new Error(`InjectedNearSigner - signature must be 64 bytes, but was ${bytes.byteLength}`);
  return bytes;
}
