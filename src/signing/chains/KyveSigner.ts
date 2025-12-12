import EthereumSigner from "./ethereumSigner.js";
import { SignatureConfig } from "../../constants";

export default class KyveSigner extends EthereumSigner {
  readonly signatureType: SignatureConfig = SignatureConfig.KYVE;
}
