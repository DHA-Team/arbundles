import { createHash, randomBytes } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import { Readable } from "stream";
import { getPublicKey, sign } from "@noble/ed25519";
import base58 from "bs58";
import { ArweaveSigner, bundleAndSignData, createData, DataItem, InjectedNearSigner, processStream } from "../../index";
import { createData as createFileData } from "../file";

// Generated with near-api-js 7.3.1 (KeyPairSigner.signNep413Message) and the published
// arbundles 1.0.4 deep hash, i.e. without any of the code under test.
const vector = {
  seed: Buffer.from("34c2672ff1bc503fd55ac2003de15d928b4e10422f00b9bdf4eeb5bf263cf805", "hex"),
  publicKey: Buffer.from("79cd91cbe7c9f27877a0b2f2a02807cda20405ab1b918d94eb654877f46ffd31", "hex"),
  publicKeyNear: "ed25519:9CU91kEC4VPzHSKBSvuevTRmSBYR2Uccr2WwYGHvWjha",
  message: Buffer.from("19865780bfbcdccbe82fb370279d6e4874373cba70f3659d3debc61b499bd3df2b22ad3ae10f13a93320749e3b0d472a", "hex"),
  nep413Message: "Upload to Arweave | Data item hash: GYZXgL-83MvoL7NwJ51uSHQ3PLpw82WdPevGG0mb098rIq064Q8TqTMgdJ47DUcq",
  signature: Buffer.from(
    "1a08e8445656128a36a94b4548ce9611ee0a3eac709e52e0c6c127e940f628977214c8c1c23760914f7717f7c51b4d0db676e38c05668ce2443b6477911a7b0b",
    "hex",
  ),
  dataItem: {
    data: "hello from a NEAR wallet",
    tags: [{ name: "Content-Type", value: "text/plain" }],
    signature: Buffer.from(
      "5f4c6f99c2d276bdbf679ac67dd8fd55768e216f74f9ce0f9b0dddc2bde26b82535f13325d2aa1a6d49e15e65e149dd67f5b62f25c5f4575edae6f582ab80c0a",
      "hex",
    ),
    id: "XkC_83LCPznGgF7xNwpApBg0ngY8xyIhtJi7hEdvg50",
  },
};

const wallet0 = JSON.parse(readFileSync(path.join(__dirname, "test_key0.json")).toString());

interface SignMessageParams {
  message: string;
  nonce: Uint8Array;
  recipient: string;
  callbackUrl?: string;
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

function borshString(s: string): Buffer {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([u32(b.byteLength), b]);
}

// NEP-413 written out independently of src/signing/nep413.ts
function nep413Digest({ message, nonce, recipient, callbackUrl }: SignMessageParams): Buffer {
  const callback = callbackUrl === undefined ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), borshString(callbackUrl)]);
  return createHash("sha256")
    .update(Buffer.concat([u32(2 ** 31 + 413), borshString(message), Buffer.from(nonce), borshString(recipient), callback]))
    .digest();
}

interface SignedMessage {
  accountId: string;
  publicKey: string | { toString(): string };
  signature: string | Uint8Array;
}

interface MockWallet {
  calls: SignMessageParams[];
  signMessage(params: SignMessageParams): Promise<SignedMessage>;
}

// A NEAR wallet's signMessage: signs with `seed`, reports `reportedKey` (defaults to its own)
function nearWallet(
  seed: Uint8Array,
  opts: { encode?: (signature: Uint8Array) => string | Uint8Array; reportedKey?: string | { toString(): string }; callbackUrl?: string } = {},
): MockWallet {
  const calls: SignMessageParams[] = [];
  return {
    calls,
    async signMessage(params: SignMessageParams): Promise<SignedMessage> {
      calls.push(params);
      const signature = await sign(nep413Digest({ ...params, callbackUrl: opts.callbackUrl ?? params.callbackUrl }), seed);
      const publicKey = "ed25519:" + base58.encode(Buffer.from(await getPublicKey(seed)));
      return {
        accountId: "alice.testnet",
        publicKey: opts.reportedKey ?? publicKey,
        signature: (opts.encode ?? ((s): string => Buffer.from(s).toString("base64")))(signature),
      };
    },
  };
}

async function connectedSigner(seed: Uint8Array = randomBytes(32)): Promise<InjectedNearSigner> {
  const signer = new InjectedNearSigner(nearWallet(seed));
  await signer.setPublicKey();
  return signer;
}

describe("InjectedNearSigner (signature type 413)", function () {
  describe("given the near-api-js known-answer vector", function () {
    it("should verify the reference signature", async function () {
      expect(await InjectedNearSigner.verify(vector.publicKey, vector.message, vector.signature)).toBe(true);
      // owners are also passed base64url-encoded
      expect(await InjectedNearSigner.verify(vector.publicKey.toString("base64url"), vector.message, vector.signature)).toBe(true);
    });

    it("should ask the wallet for exactly the reference payload and return its signature", async function () {
      const wallet = nearWallet(vector.seed);
      const signer = new InjectedNearSigner(wallet, vector.publicKeyNear);
      expect(Buffer.from(await signer.sign(vector.message))).toEqual(vector.signature);
      expect(wallet.calls).toHaveLength(1);
      expect(wallet.calls[0]).toEqual({
        message: vector.nep413Message,
        nonce: createHash("sha256").update(vector.message).digest(),
        recipient: "arweave",
      });
    });

    it("should create the reference data item", async function () {
      const signer = new InjectedNearSigner(nearWallet(vector.seed), vector.publicKey);
      const item = createData(vector.dataItem.data, signer, { tags: vector.dataItem.tags });
      await item.sign(signer);
      expect(item.id).toEqual(vector.dataItem.id);
      expect(item.rawSignature).toEqual(vector.dataItem.signature);
      expect(item.signatureType).toEqual(413);
      expect(item.rawOwner).toEqual(vector.publicKey);
      expect(await DataItem.verify(item.getRaw())).toBe(true);
    });
  });

  describe("given a connected wallet", function () {
    it("should hand the wallet a Buffer nonce, which @near-wallet-selector requires", async function () {
      const wallet = nearWallet(vector.seed);
      const signer = new InjectedNearSigner(wallet);
      await signer.setPublicKey();
      await signer.sign(vector.message);
      expect(wallet.calls.map((c) => Buffer.isBuffer(c.nonce))).toEqual([true, true]);
    });

    it("should accept a key reported as a near-api-js PublicKey object", async function () {
      const reportedKey = { toString: (): string => vector.publicKeyNear };
      const signer = new InjectedNearSigner(nearWallet(vector.seed, { reportedKey }));
      await signer.setPublicKey();
      expect(signer.publicKey).toEqual(vector.publicKey);
      expect(new InjectedNearSigner(nearWallet(vector.seed), reportedKey).publicKey).toEqual(vector.publicKey);
    });

    it("should learn the signing key from a probe signature", async function () {
      const wallet = nearWallet(vector.seed);
      const signer = new InjectedNearSigner(wallet);
      expect(signer.publicKey).toBeUndefined();
      await signer.setPublicKey();
      expect(signer.publicKey).toEqual(vector.publicKey);
      await signer.setPublicKey();
      // the probe can never be mistaken for a data item signature, nor replayed
      expect(wallet.calls[0].message.startsWith("Upload to Arweave")).toBe(false);
      expect(wallet.calls[0].nonce).not.toEqual(wallet.calls[1].nonce);
    });

    it("should create valid data items, bundles and file data items", async function () {
      const signer = await connectedSigner();
      const opts = {
        target: "OXcT1sVRSA5eGwt2k6Yuz8-3e3g9WJi5uSE99CWqsBs",
        anchor: "Math.apt'#]gng(36).substring(30)",
        tags: [{ name: "Content-Type", value: "image/png" }],
      };
      const nearItem = createData("hello", signer, opts);
      await nearItem.sign(signer);
      expect(await nearItem.isValid()).toBe(true);

      // alongside an Arweave-signed item, as a bundler would pack them
      const bundle = await bundleAndSignData([nearItem, createData("world", new ArweaveSigner(wallet0))], new ArweaveSigner(wallet0));
      expect(await bundle.verify()).toBe(true);
      const indexed = await processStream(Readable.from(bundle.getRaw()));
      expect(indexed.map((i) => i.sigName)).toEqual(["injectedNear", "arweave"]);
      expect(indexed[0].id).toEqual(nearItem.id);

      const fileItem = await createFileData("hello", signer, opts);
      await fileItem.sign(signer);
      expect(await fileItem.isValid()).toBe(true);
    });

    it.each([
      ["base64", (s: Uint8Array): string => Buffer.from(s).toString("base64")],
      ["base64url", (s: Uint8Array): string => Buffer.from(s).toString("base64url")],
      ["ed25519:base58", (s: Uint8Array): string => "ed25519:" + base58.encode(Buffer.from(s))],
      ["raw bytes", (s: Uint8Array): Uint8Array => s],
    ])("should accept a %s signature", async function (_, encode) {
      const signer = new InjectedNearSigner(nearWallet(vector.seed, { encode }), vector.publicKey);
      expect(Buffer.from(await signer.sign(vector.message))).toEqual(vector.signature);
    });
  });

  describe("given an invalid signature", function () {
    const digestFor = (params: Partial<SignMessageParams>): Buffer =>
      nep413Digest({
        message: vector.nep413Message,
        nonce: createHash("sha256").update(vector.message).digest(),
        recipient: "arweave",
        ...params,
      });

    it.each([
      ["a type 2 signature over the raw deep hash", async (): Promise<Uint8Array> => sign(vector.message, vector.seed)],
      ["a different recipient", async (): Promise<Uint8Array> => sign(digestFor({ recipient: "ar.io" }), vector.seed)],
      ["a random nonce", async (): Promise<Uint8Array> => sign(digestFor({ nonce: randomBytes(32) }), vector.seed)],
      ["a callbackUrl", async (): Promise<Uint8Array> => sign(digestFor({ callbackUrl: "https://example.com" }), vector.seed)],
      ["a different message", async (): Promise<Uint8Array> => sign(digestFor({ message: vector.nep413Message + " " }), vector.seed)],
    ])("should reject %s", async function (_, signature) {
      expect(await InjectedNearSigner.verify(vector.publicKey, vector.message, await signature())).toBe(false);
    });

    it("should return false, not throw, for an owner that is not a valid curve point", async function () {
      expect(await InjectedNearSigner.verify(Buffer.alloc(32, 2), vector.message, vector.signature)).toBe(false);
    });

    it("should reject a small-order owner, whose signatures need no private key", async function () {
      expect(await InjectedNearSigner.verify(Buffer.alloc(32), vector.message, Buffer.alloc(64))).toBe(false);
    });

    it("should reject a tampered data item", async function () {
      const signer = await connectedSigner();
      const item = createData("hello", signer);
      await item.sign(signer);
      const raw = item.getRaw();
      raw[raw.byteLength - 1] ^= 1;
      expect(await DataItem.verify(raw)).toBe(false);
    });
  });

  describe("given a misbehaving wallet", function () {
    it("should refuse to sign before the key is known", async function () {
      await expect(new InjectedNearSigner(nearWallet(vector.seed)).sign(vector.message)).rejects.toThrow("setPublicKey");
      // as when a connector reports an empty key
      await expect(new InjectedNearSigner(nearWallet(vector.seed), "").sign(vector.message)).rejects.toThrow("setPublicKey");
    });

    it("should reject a wallet that returns nothing", async function () {
      const signer = new InjectedNearSigner({ signMessage: async (): Promise<undefined> => undefined }, vector.publicKey);
      await expect(signer.sign(vector.message)).rejects.toThrow("no signature");
      await expect(signer.setPublicKey()).rejects.toThrow("no signature");
    });

    it.each([
      ["no key", "", "did not return its public key"],
      ["a key that is not ed25519", "secp256k1:" + base58.encode(randomBytes(64)), "only ed25519"],
      ["a key of the wrong length", "ed25519:" + base58.encode(randomBytes(31)), "32 bytes"],
    ])("should reject a probe that reports %s", async function (_, reportedKey, error) {
      const signer = new InjectedNearSigner(nearWallet(vector.seed, { reportedKey }));
      await expect(signer.setPublicKey()).rejects.toThrow(error);
    });

    it.each([
      ["another key", (): Promise<Uint8Array> => getPublicKey(createHash("sha256").update("another key").digest())],
      ["an invalid curve point", async (): Promise<Uint8Array> => Buffer.alloc(32, 2)],
    ])("should reject a reported key that did not make the signature (%s)", async function (_, reportedKey) {
      const signer = new InjectedNearSigner(nearWallet(vector.seed, { reportedKey: "ed25519:" + base58.encode(Buffer.from(await reportedKey())) }));
      await expect(signer.setPublicKey()).rejects.toThrow("does not match");
      expect(signer.publicKey).toBeUndefined();
    });

    it("should reject a signature from another key than the owner", async function () {
      const signer = new InjectedNearSigner(nearWallet(randomBytes(32)), vector.publicKey);
      await expect(signer.sign(vector.message)).rejects.toThrow("another key than the owner");
    });

    it("should reject a wallet that signs a callbackUrl, as MyNearWallet does", async function () {
      const wallet = nearWallet(vector.seed, { callbackUrl: "https://console.ar.io/upload" });
      await expect(new InjectedNearSigner(wallet).setPublicKey()).rejects.toThrow("callbackUrl");
      await expect(new InjectedNearSigner(wallet, vector.publicKey).sign(vector.message)).rejects.toThrow("altered the payload");
    });

    it("should reject a signature of the wrong length", async function () {
      const signer = new InjectedNearSigner(nearWallet(vector.seed, { encode: (s): Uint8Array => s.subarray(0, 63) }), vector.publicKey);
      await expect(signer.sign(vector.message)).rejects.toThrow("64 bytes");
    });
  });
});
