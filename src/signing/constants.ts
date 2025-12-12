import type { Signer } from "./Signer";
import Curve25519 from "./keys/curve25519";

import {
  ArweaveSigner,
  EthereumSigner,
  HexInjectedSolanaSigner,
  InjectedAptosSigner,
  KyveSigner,
  MultiSignatureAptosSigner,
  TypedEthereumSigner,
} from "./chains/index";
import { SignatureConfig } from "../constants";

export type IndexToType = Record<
  SignatureConfig,
  {
    new (...args): Signer;
    verify(pk: string | Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
  }
>;

const { ARWEAVE, ED25519, ETHEREUM, INJECTEDAPTOS, KYVE, MULTIAPTOS, SOLANA, TYPEDETHEREUM } = SignatureConfig;

export const indexToType: IndexToType = {
  [ARWEAVE]: ArweaveSigner,
  [ED25519]: Curve25519,
  [ETHEREUM]: EthereumSigner,
  [SOLANA]: HexInjectedSolanaSigner,
  [INJECTEDAPTOS]: InjectedAptosSigner,
  [MULTIAPTOS]: MultiSignatureAptosSigner,
  [TYPEDETHEREUM]: TypedEthereumSigner,
  [KYVE]: KyveSigner,
};
