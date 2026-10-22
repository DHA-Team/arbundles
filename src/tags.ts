import { MAX_TAG_BYTES } from "./DataItem";

export interface Tag {
  name: string;
  value: string;
}

export interface RawTag {
  name: Buffer;
  value: Buffer;
}

export class AVSCTap {
  protected buf: Buffer;
  protected pos: number;

  constructor(buf = Buffer.alloc(MAX_TAG_BYTES), pos = 0) {
    this.buf = buf;
    this.pos = pos;
  }

  public writeTags(tags: Tag[]): void {
    if (!Array.isArray(tags)) {
      throw new Error("input must be array");
    }

    const n = tags.length;
    let i;
    if (n) {
      this.writeLong(n);
      for (i = 0; i < n; i++) {
        // for this use case, assume tags/strings.
        const tag = tags[i];
        if (typeof tag?.name !== "string" || typeof tag?.value !== "string")
          throw new Error(`Invalid tag format for ${tag}, expected {name:string, value: string}`);
        this.writeString(tag.name);
        this.writeString(tag.value);
        // this.itemsType._write(tap, val[i]);
      }
    }
    this.writeLong(0);
  }

  public writeRawTags(tags: RawTag[]): void {
    if (!tags.length) return;
    this.writeLong(tags.length);
    for (const bytes of tags.flatMap(({ name, value }) => [name, value])) {
      this.writeLong(bytes.length);
      bytes.copy(this.buf, this.pos);
      this.pos += bytes.length;
    }
    this.writeLong(0);
  }

  public toBuffer(): Buffer {
    const buffer = Buffer.alloc(this.pos);
    if (this.pos > this.buf.length) throw new Error(`Too many tag bytes (${this.pos} > ${this.buf.length})`);
    this.buf.copy(buffer, 0, 0, this.pos);
    return buffer;
  }

  protected writeLong(n: number): void {
    const buf = this.buf;
    let f, m;

    if (n >= -1073741824 && n < 1073741824) {
      // Won't overflow, we can use integer arithmetic.
      m = n >= 0 ? n << 1 : (~n << 1) | 1;
      do {
        buf[this.pos] = m & 0x7f;
        m >>= 7;
      } while (m && (buf[this.pos++] |= 0x80));
    } else {
      // We have to use slower floating arithmetic.
      f = n >= 0 ? n * 2 : -n * 2 - 1;
      do {
        buf[this.pos] = f & 0x7f;
        f /= 128;
      } while (f >= 1 && (buf[this.pos++] |= 0x80));
    }
    this.pos++;
    this.buf = buf;
  }

  // for some reason using setters/getters with ++ doesn't work right.
  // set pos(newPos: number) {
  //   const d = newPos + 1 - this.buf.length;
  //   if (d > 0) this.buf = Buffer.concat([this.buf, Buffer.alloc(d)]);
  //   this._pos = newPos;
  // }

  // get pos(): number {
  //   return this._pos;
  // }

  // protected safeRead(position): number {
  //   return position > this.buf.length ? 0 : this.buf[position];
  // }
  // protected safeWrite(position, value): Buffer {
  //   if (position > this.buf.length) this.buf = Buffer.concat([this.buf, Buffer.alloc(1)]);
  //   this.buf[position] = value;
  //   return this.buf;
  // }

  protected writeString(s: string): void {
    const len = Buffer.byteLength(s);
    const buf = this.buf;
    this.writeLong(len);
    let pos = this.pos;
    this.pos += len;
    if (this.pos > buf.length) {
      return;
    }
    if (len > 64) {
      // this._writeUtf8(s, len);
      this.buf.write(s, this.pos - len, len, "utf8");
    } else {
      let i, l, c1, c2;
      for (i = 0, l = len; i < l; i++) {
        c1 = s.charCodeAt(i);
        if (c1 < 0x80) {
          buf[pos++] = c1;
        } else if (c1 < 0x800) {
          buf[pos++] = (c1 >> 6) | 0xc0;
          buf[pos++] = (c1 & 0x3f) | 0x80;
        } else if ((c1 & 0xfc00) === 0xd800 && ((c2 = s.charCodeAt(i + 1)) & 0xfc00) === 0xdc00) {
          c1 = 0x10000 + ((c1 & 0x03ff) << 10) + (c2 & 0x03ff);
          i++;
          buf[pos++] = (c1 >> 18) | 0xf0;
          buf[pos++] = ((c1 >> 12) & 0x3f) | 0x80;
          buf[pos++] = ((c1 >> 6) & 0x3f) | 0x80;
          buf[pos++] = (c1 & 0x3f) | 0x80;
        } else {
          buf[pos++] = (c1 >> 12) | 0xe0;
          buf[pos++] = ((c1 >> 6) & 0x3f) | 0x80;
          buf[pos++] = (c1 & 0x3f) | 0x80;
        }
      }
    }
    this.buf = buf;
  }

  protected readLong(): number {
    let n = 0;
    let k = 0;
    const buf = this.buf;
    let b, h, f, fk;

    do {
      // A number cut off by the end of the input keeps the value read so far
      b = this.pos < buf.length ? buf[this.pos++] : 0;
      h = b & 0x80;
      n |= (b & 0x7f) << k;
      k += 7;
    } while (h && k < 28);

    if (h) {
      // Switch to float arithmetic, otherwise we might overflow.
      f = n;
      fk = 268435456; // 2 ** 28.
      do {
        b = this.pos < buf.length ? buf[this.pos++] : 0;
        f += (b & 0x7f) * fk;
        fk *= 128;
      } while (b & 0x80);
      return (f % 2 ? -(f + 1) : f) / 2;
    }

    return (n >> 1) ^ -(n & 1);
  }

  protected skipLong(): void {
    const buf = this.buf;
    while (buf[this.pos++] & 0x80) {}
  }

  public readTags(): Tag[] {
    return this.readRawTags().map(({ name, value }) => ({ name: name.toString(), value: value.toString() }));
  }

  public readRawTags(): RawTag[] {
    const val: RawTag[] = [];
    const buf = this.buf;
    let n;
    for (;;) {
      if (this.pos >= buf.length) throw new Error("Invalid ANS-104 tags: missing terminator");
      if (!(n = this.readLong())) break;
      if (n < 0) {
        n = -n;
        const size = this.readLong();
        if (size < 0 || size > buf.length - this.pos) throw new Error("Invalid ANS-104 tags: invalid block size");
        this.buf = buf.subarray(0, this.pos + size);
      }
      while (n-- > 0) {
        if (this.pos >= this.buf.length) throw new Error("Invalid ANS-104 tags: truncated tag");
        const name = this.readBytes();
        // A name length of 0 ends the block
        if (!name.length) break;
        val.push({ name, value: this.readBytes() });
      }
      if (this.buf !== buf && this.pos !== this.buf.length) throw new Error("Invalid ANS-104 tags: bytes left in block");
      this.buf = buf;
    }
    if (this.pos !== buf.length) throw new Error("Invalid ANS-104 tags: bytes after terminator");
    return val;
  }

  protected readBytes(): Buffer {
    const len = this.readLong();
    const pos = this.pos;
    const buf = this.buf;
    this.pos += len;
    if (len < 0 || this.pos > buf.length) {
      // return undefined;
      throw new Error("TAP Position out of range");
    }
    return buf.subarray(pos, pos + len);
  }
}

export function serializeTags(tags: Tag[]): Buffer {
  if (tags?.length === 0) {
    return Buffer.allocUnsafe(0);
  }
  const tap = new AVSCTap();
  tap.writeTags(tags);
  return tap.toBuffer();
}
export function deserializeTags(tagsBuffer: Buffer): Tag[] {
  const tap = new AVSCTap(tagsBuffer);
  return tap.readTags();
}

export function verifyTagSection(numberOfTags: number, tagsBuffer: Buffer): Buffer {
  if (numberOfTags === 0 && tagsBuffer.length === 0) return tagsBuffer;
  const tags = new AVSCTap(tagsBuffer).readRawTags();
  if (tags.length !== numberOfTags) throw new Error("Invalid ANS-104 tags: tag count mismatch");
  for (const { name } of tags) {
    if (!Buffer.from(name.toString()).equals(name)) throw new Error("Invalid ANS-104 tags: tag name not UTF-8");
  }
  return signedTagBytes(tagsBuffer);
}

export function signedTagBytes(tagsBuffer: Buffer): Buffer {
  try {
    const tap = new AVSCTap(Buffer.alloc(tagsBuffer.length + 16)); // re-encoding adds at most a few bytes
    tap.writeRawTags(new AVSCTap(tagsBuffer).readRawTags());
    return tap.toBuffer();
  } catch (e) {
    return tagsBuffer;
  }
}
