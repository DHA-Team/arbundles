import base64url from "base64url";
import { getCryptoDriver } from "$/utils";
import { longToNByteArray } from "../utils";

// NEAR wallets cannot sign raw bytes: their signMessage (NEP-413,
// https://github.com/near/NEPs/blob/master/neps/nep-0413.md) signs sha256 of a tagged,
// borsh-serialized { message, nonce, recipient, callbackUrl } payload. Signature type 413
// derives every field of that payload from the data item's deep hash, so verifying needs
// nothing but the item itself.

export const NEP413_TAG = 2 ** 31 + 413;
export const NEP413_RECIPIENT = "arweave";
export const NEP413_MESSAGE_PREFIX = "Upload to Arweave | Data item hash: ";

export interface Nep413Payload {
  message: string;
  nonce: Uint8Array;
  recipient: string;
}

/** The payload a wallet is asked to sign for a data item, given its deep hash. */
export async function nep413Payload(deepHash: Uint8Array): Promise<Nep413Payload> {
  return {
    message: NEP413_MESSAGE_PREFIX + base64url.encode(Buffer.from(deepHash)),
    nonce: await getCryptoDriver().hash(deepHash, "SHA-256"),
    recipient: NEP413_RECIPIENT,
  };
}

/** The 32 bytes an NEP-413 signature is an ed25519 signature over. */
export async function nep413Digest({ message, nonce, recipient }: Nep413Payload): Promise<Uint8Array> {
  if (nonce.byteLength !== 32) throw new Error(`NEP-413 nonce must be 32 bytes, but was ${nonce.byteLength}`);
  return getCryptoDriver().hash(
    Buffer.concat([
      longToNByteArray(4, NEP413_TAG),
      borshString(message),
      nonce,
      borshString(recipient),
      Uint8Array.of(0), // callbackUrl: None
    ]),
    "SHA-256",
  );
}

function borshString(s: string): Buffer {
  const bytes = Buffer.from(s, "utf8");
  return Buffer.concat([longToNByteArray(4, bytes.byteLength), bytes]);
}
