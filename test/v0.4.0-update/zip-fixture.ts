/** TEST-ONLY deterministic ZIP32 fixture builder for hostile archive cases. */
import { deflateRawSync } from "node:zlib";

export interface TestZipEntry {
  readonly name: string;
  readonly data: Uint8Array;
  readonly method?: 0 | 8;
  readonly flags?: number;
  readonly host?: 0 | 3;
  readonly unixMode?: number;
  readonly externalFileAttributes?: number;
  readonly centralExtra?: Uint8Array;
  readonly localExtra?: Uint8Array;
  readonly comment?: Uint8Array;
  readonly versionNeeded?: number;
  readonly localName?: string;
  readonly crc32?: number;
  /** Override the central-directory local-header offset (for overlapping-entry tests). */
  readonly localOffset?: number;
  /** If false, omit this entry's local header from the concatenated local bytes (default: true). */
  readonly includeLocal?: boolean;
}

export interface TestZipOptions {
  readonly prefix?: Uint8Array;
  readonly suffix?: Uint8Array;
  readonly comment?: Uint8Array;
}

interface BuiltEntry {
  readonly local: Buffer;
  readonly central: Buffer;
}

export function buildTestZip(
  entries: readonly TestZipEntry[],
  options: TestZipOptions = {},
): Buffer {
  const prefix = Buffer.from(options.prefix ?? []);
  let localOffset = prefix.byteLength;
  const built: BuiltEntry[] = [];
  const localParts: Buffer[] = [];
  for (const input of entries) {
    const data = Buffer.from(input.data);
    const method = input.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(data, { level: 9 }) : data;
    const name = Buffer.from(input.name, "utf8");
    const localName = Buffer.from(input.localName ?? input.name, "utf8");
    const localExtra = Buffer.from(input.localExtra ?? []);
    const centralExtra = Buffer.from(input.centralExtra ?? []);
    const comment = Buffer.from(input.comment ?? []);
    const flags = input.flags ?? 0x0800;
    const crc = input.crc32 ?? crc32(data);
    const versionNeeded = input.versionNeeded ?? 20;
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(versionNeeded, 4);
    localHeader.writeUInt16LE(flags, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc >>> 0, 14);
    localHeader.writeUInt32LE(compressed.byteLength, 18);
    localHeader.writeUInt32LE(data.byteLength, 22);
    localHeader.writeUInt16LE(localName.byteLength, 26);
    localHeader.writeUInt16LE(localExtra.byteLength, 28);
    const local = Buffer.concat([
      localHeader,
      localName,
      localExtra,
      compressed,
    ]);

    const host = input.host ?? 3;
    const unixMode = input.unixMode ?? 0o100644;
    const external =
      input.externalFileAttributes ??
      (host === 3 ? (unixMode << 16) >>> 0 : 0x20);
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE((host << 8) | 20, 4);
    centralHeader.writeUInt16LE(versionNeeded, 6);
    centralHeader.writeUInt16LE(flags, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc >>> 0, 16);
    centralHeader.writeUInt32LE(compressed.byteLength, 20);
    centralHeader.writeUInt32LE(data.byteLength, 24);
    centralHeader.writeUInt16LE(name.byteLength, 28);
    centralHeader.writeUInt16LE(centralExtra.byteLength, 30);
    centralHeader.writeUInt16LE(comment.byteLength, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(external >>> 0, 38);
    centralHeader.writeUInt32LE(input.localOffset ?? localOffset, 42);
    const central = Buffer.concat([centralHeader, name, centralExtra, comment]);
    built.push({ local, central });
    if (input.includeLocal !== false) {
      localParts.push(local);
      localOffset += local.byteLength;
    }
  }

  const localBytes = Buffer.concat(localParts);
  const centralBytes = Buffer.concat(built.map((entry) => entry.central));
  const archiveComment = Buffer.from(options.comment ?? []);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBytes.byteLength, 12);
  eocd.writeUInt32LE(prefix.byteLength + localBytes.byteLength, 16);
  eocd.writeUInt16LE(archiveComment.byteLength, 20);
  return Buffer.concat([
    prefix,
    localBytes,
    centralBytes,
    eocd,
    archiveComment,
    Buffer.from(options.suffix ?? []),
  ]);
}

export function buildEntryLocalBytes(input: TestZipEntry): Buffer {
  const data = Buffer.from(input.data);
  const method = input.method ?? 0;
  const compressed = method === 8 ? deflateRawSync(data, { level: 9 }) : data;
  const localName = Buffer.from(input.localName ?? input.name, "utf8");
  const localExtra = Buffer.from(input.localExtra ?? []);
  const flags = input.flags ?? 0x0800;
  const crc = input.crc32 ?? crc32(data);
  const versionNeeded = input.versionNeeded ?? 20;
  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(versionNeeded, 4);
  localHeader.writeUInt16LE(flags, 6);
  localHeader.writeUInt16LE(method, 8);
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(crc >>> 0, 14);
  localHeader.writeUInt32LE(compressed.byteLength, 18);
  localHeader.writeUInt32LE(data.byteLength, 22);
  localHeader.writeUInt16LE(localName.byteLength, 26);
  localHeader.writeUInt16LE(localExtra.byteLength, 28);
  return Buffer.concat([localHeader, localName, localExtra, compressed]);
}

const CRC_TABLE = makeCrcTable();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeCrcTable(): Uint32Array {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
}
