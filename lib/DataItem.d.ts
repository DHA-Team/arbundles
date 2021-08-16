/// <reference types="node" />
import { Buffer } from 'buffer';
import { JWKPublicInterface } from './interface-jwk';
export declare const MIN_BINARY_SIZE = 1042;
export default class DataItem {
    private readonly binary;
    private id;
    constructor(binary: Buffer);
    static isDataItem(obj: any): boolean;
    isValid(): boolean;
    getRawId(): Buffer;
    getId(): string;
    getRawSignature(): Buffer;
    getSignature(): string;
    getRawOwner(): Buffer;
    getOwner(): string;
    getAddress(): Promise<string>;
    getRawTarget(): Buffer;
    getTarget(): string;
    getRawAnchor(): Buffer;
    getAnchor(): string;
    getRawTags(): Buffer;
    getTags(): {
        name: string;
        value: string;
    }[];
    getStartOfData(): number;
    getData(): Buffer;
    /**
     * UNSAFE!!
     * DO NOT MUTATE THE BINARY ARRAY. THIS WILL CAUSE UNDEFINED BEHAVIOUR.
     */
    getRaw(): Buffer;
    sign(jwk: JWKPublicInterface): Promise<Buffer>;
    isSigned(): boolean;
    /**
     * Returns a JSON representation of a DataItem
     */
    toJSON(): {
        owner: string;
        data: string;
        signature: string;
        target: string;
        tags: {
            name: string;
            value: string;
        }[];
    };
    /**
     * Verifies a `Buffer` and checks it fits the format of a DataItem
     *
     * A binary is valid iff:
     * - the tags are encoded correctly
     */
    static verify(buffer: Buffer, extras?: {
        id: Uint8Array;
        jwk: JWKPublicInterface;
    }): boolean;
    /**
     * Returns the start byte of the tags section (number of tags)
     *
     * @private
     */
    private getTagsStart;
    /**
     * Returns the start byte of the tags section (number of tags)
     *
     * @private
     */
    private getTargetStart;
    /**
     * Returns the start byte of the tags section (number of tags)
     *
     * @private
     */
    private getAnchorStart;
}
