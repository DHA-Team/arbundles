import type DataItem from "./DataItem";
import { deepHash, stringToBuffer } from "$/utils";
import { signedTagBytes } from "./tags";
/**
 * Options for creation of a DataItem
 */
export interface DataItemCreateOptions {
  target?: string;
  anchor?: string;
  tags?: { name: string; value: string }[];
}

async function getSignatureData(item: DataItem): Promise<Uint8Array> {
  return deepHash([
    stringToBuffer("dataitem"),
    stringToBuffer("1"),
    stringToBuffer(item.signatureType.toString()),
    item.rawOwner,
    item.rawTarget,
    item.rawAnchor,
    signedTagBytes(item.rawTags),
    item.rawData,
  ]);
}

export default getSignatureData;
