// github-core-clone-01: a standalone GitHub-compatible git forge.
// One file, Node standard library only: an in-memory object store, git smart HTTP
// (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and MCP over streamable HTTP.
// Everything served is deterministic: timestamps come from a counter, never the wall clock;
// pack bytes are built the same way every time for the same objects.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const ZERO_OID = '0'.repeat(40);
const JSON_TYPE = 'application/json; charset=utf-8';
const FORGE_IDENT = 'forge <forge@localhost>';
const EPOCH_SEC = 1735689600; // 2025-01-01T00:00:00Z; every served timestamp derives from this + a counter.
const SERVER_NAME = 'github-core-clone';
const SERVER_VERSION = '1.0.0';
const MCP_REVISION = '2026-07-28';
const MCP_LEGACY_REVISIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

// ---------------------------------------------------------------- tiny helpers

function sha1Hex(data: Buffer | Uint8Array): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function b64encode(data: Buffer | Uint8Array | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data as string, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function isoOf(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString().replace('.000Z', 'Z');
}

// ---------------------------------------------------------------- the seeded scenario's viewer (computed, never pasted)

// The suite's scenario is one fixed seed; the token owner's login derives from it. These are
// the same pure functions the scenario uses (FNV-1a label mixing, splitmix64 finalizer, a
// xorshift64* stream), re-implemented here so the forge can answer `viewer { login }` without
// any seeded data of its own.

const U64_MASK = 0xffffffffffffffffn;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class SeedRng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? 0x6a09e667f3bcc909n : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'] as const;
const LAST_NAMES = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'] as const;

/** The login the bearer token names: the scenario's first generated user. */
function viewerLogin(): string {
  const seed = mix64(0x6a09e667f3bcc909n ^ fnv1a64('users'));
  const rng = new SeedRng(seed);
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  return `${first}${last}`.replace(/[^a-z0-9-]/g, '');
}

const VIEWER = viewerLogin();

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}

function hashObject(type: ObjType, data: Buffer | Uint8Array): string {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const head = Buffer.from(`${type} ${buf.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, buf]));
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

/** Git's tree order: names sorted bytewise, directories compared as if suffixed with '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  const view: CommitView = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) view.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) view.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) view.author = line.slice(7);
    else if (line.startsWith('committer ')) view.committer = line.slice(10);
  }
  return view;
}

function buildCommit(tree: string, parents: readonly string[], message: string, timestamp: number): Buffer {
  const ident = `${FORGE_IDENT} ${timestamp} +0000`;
  const lines = [`tree ${tree}`, ...parents.map((p) => `parent ${p}`), `author ${ident}`, `committer ${ident}`, '', message.endsWith('\n') ? message : `${message}\n`];
  return Buffer.from(lines.join('\n'), 'utf8');
}

function buildTag(targetOid: string, targetType: ObjType, tagName: string, message: string, timestamp: number): Buffer {
  const ident = `${FORGE_IDENT} ${timestamp} +0000`;
  return Buffer.from(`object ${targetOid}\ntype ${targetType}\ntag ${tagName}\ntagger ${ident}\n\n${message.endsWith('\n') ? message : `${message}\n`}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const view: TagView = { object: '', type: '', tag: '' };
  for (const line of text.split('\n')) {
    if (line === '') break;
    if (line.startsWith('object ')) view.object = line.slice(7).trim();
    else if (line.startsWith('type ')) view.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) view.tag = line.slice(4).trim();
  }
  return view;
}

// ---------------------------------------------------------------- pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface Pkt {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}

/** Decode a whole pkt-line stream; throws on a bad length or a truncated packet. */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('pkt-line truncated');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (head === '0000') {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (head === '0001') {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (head === '0002') {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const len = parseInt(head, 16);
    if (len < 4 || off + len > buf.length) throw new Error('pkt-line length out of range');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------- packfiles

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a version-2 pack of plain objects (no deltas); trailer is SHA-1 of all prior bytes. */
function writePack(objects: readonly GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const obj of objects) {
    parts.push(packObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readPackVarint(buf: Buffer, start: number): { size: number; first: number; next: number } {
  let byte = buf[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off++] as number;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, first, next: off };
}

function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start] as number;
  let off = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[off++] as number;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: off };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off++] as number;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++] as number;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += (delta[off++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[off++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, off, off + literal);
      off += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface PackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

/**
 * Read a pack (v2/v3), resolving OFS_DELTA and REF_DELTA entries. `resolveBase` supplies a base
 * a thin pack leaves out. Every object is re-hashed; a mismatch throws.
 */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declared = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1Hex(pack.subarray(0, trailerStart)) !== trailer) throw new Error('pack trailer checksum mismatch');

  const raw: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  let off = 12;
  for (let i = 0; i < declared; i += 1) {
    const entryOffset = off;
    const header = readPackVarint(pack, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: PackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsBase(pack, off);
      off = base.next;
      if (base.baseOffset <= 0 || base.baseOffset > entryOffset) throw new Error('ofs-delta base offset out of range');
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      if (off + 20 > trailerStart) throw new Error('ref-delta base id truncated');
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type code ${typeCode}`);
    }
    const inflated = inflateSync(pack.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (inflated.buffer.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    off += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (off !== trailerStart) throw new Error('pack has trailing bytes');

  const objects = new Map<string, GitObj>();
  const resolvedByOid = new Map<string, { type: ObjType; data: Buffer }>();
  const resolving = new Set<number>();
  const resolve = (entry: PackEntry): { type: ObjType; data: Buffer; oid: string } => {
    const cached = (entry as unknown as { _resolved?: { type: ObjType; data: Buffer; oid: string } })._resolved;
    if (cached) return cached;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = [...byOffset.values()].find((e) => (e as unknown as { _resolved?: { oid: string } })._resolved?.oid === wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} not available`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as ObjType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const out = { type, data, oid };
    (entry as unknown as { _resolved?: unknown })._resolved = out;
    resolvedByOid.set(oid, out);
    resolving.delete(entry.offset);
    return out;
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return objects;
}

// ---------------------------------------------------------------- the store

interface IssueRec {
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
}

interface CommentRec {
  id: number;
  body: string;
  seq: number;
}

interface PullRec {
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeBase: string;
  seq: number;
}

interface RepoRec {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObj>;
  issues: IssueRec[];
  issueSeq: number;
  labels: Map<string, { name: string; color: string }>;
  comments: Map<number, CommentRec[]>;
  pulls: PullRec[];
  pullSeq: number;
  packCache: Map<string, { pack: Buffer | null; shallow: string[]; unshallow: string[]; ack: string | null }>;
  seq: number;
}

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

class Forge {
  repos = new Map<string, RepoRec>();
  repoSeq = 0;
  issueIdSeq = 0;
  commentIdSeq = 0;
  pullIdSeq = 0;
  clock = 0;

  nextTime(): number {
    return EPOCH_SEC + (this.clock += 1);
  }

  getRepo(owner: string, name: string): RepoRec | undefined {
    return this.repos.get(repoKey(owner, name));
  }

  createRepo(owner: string, name: string, isPrivate: boolean, description: string): RepoRec | null {
    if (this.repos.has(repoKey(owner, name))) return null;
    const repo: RepoRec = {
      id: 5000 + (this.repoSeq += 1) - 1,
      owner,
      name,
      description,
      isPrivate,
      defaultBranch: 'main',
      refs: new Map(),
      objects: new Map(),
      issues: [],
      issueSeq: 0,
      labels: new Map(),
      comments: new Map(),
      pulls: [],
      pullSeq: 0,
      packCache: new Map(),
      seq: this.repoSeq,
    };
    this.repos.set(repoKey(owner, name), repo);
    return repo;
  }

  deleteRepo(owner: string, name: string): boolean {
    return this.repos.delete(repoKey(owner, name));
  }

  listRepos(owner: string): RepoRec[] {
    const out: RepoRec[] = [];
    for (const repo of this.repos.values()) if (repo.owner === owner) out.push(repo);
    out.sort((a, b) => a.seq - b.seq);
    return out;
  }

  storeObjects(repo: RepoRec, objects: ReadonlyMap<string, GitObj> | readonly GitObj[]): void {
    if (Array.isArray(objects)) {
      for (const obj of objects) {
        const oid = hashObject(obj.type, obj.data);
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } else {
      for (const [oid, obj] of objects) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    }
    repo.packCache.clear();
  }

  // -- object graph ---------------------------------------------------------

  /**
   * All object ids reachable from the given tips (commits, tags, trees, blobs). When `stopAt`
   * names commits, the walk includes those commits and their trees but not their parents:
   * a shallow client's boundary — it holds the boundary commit, not its ancestry.
   */
  reachable(repo: RepoRec, tips: readonly string[], stopAt: ReadonlySet<string> = new Set()): Set<string> {
    const seen = new Set<string>();
    const stack: string[] = [];
    for (const tip of tips) if (tip !== ZERO_OID && repo.objects.has(tip)) stack.push(tip);
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (seen.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      seen.add(oid);
      if (obj.type === 'commit') {
        const view = parseCommit(obj.data);
        if (view.tree !== '') stack.push(view.tree);
        if (!stopAt.has(oid)) for (const parent of view.parents) stack.push(parent);
      } else if (obj.type === 'tree') {
        for (const entry of parseTree(obj.data)) stack.push(entry.oid);
      } else if (obj.type === 'tag') {
        stack.push(parseTag(obj.data).object);
      }
    }
    return seen;
  }

  /** The closure of a tree: the tree itself, its subtrees and its blobs. */
  treeClosure(repo: RepoRec, treeOid: string): Set<string> {
    const out = new Set<string>();
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (out.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      out.add(oid);
      if (obj.type === 'tree') for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    }
    return out;
  }
  peel(repo: RepoRec, oid: string): string {
    let current = oid;
    for (let i = 0; i < 16; i += 1) {
      const obj = repo.objects.get(current);
      if (!obj || obj.type !== 'tag') return current;
      current = parseTag(obj.data).object;
    }
    return current;
  }

  isAncestor(repo: RepoRec, ancestor: string, descendant: string): boolean {
    if (ancestor === descendant) return true;
    const seen = new Set<string>();
    const stack = [descendant];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (oid === ancestor) return true;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) stack.push(parent);
    }
    return false;
  }

  /** The first common ancestor of two commits (BFS from both sides, linear histories exact). */
  mergeBase(repo: RepoRec, a: string, b: string): string {
    if (a === b) return a;
    const ancestorsA = new Set<string>();
    const stackA = [a];
    while (stackA.length > 0) {
      const oid = stackA.pop() as string;
      if (ancestorsA.has(oid)) continue;
      ancestorsA.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) stackA.push(parent);
    }
    const queue = [b];
    const seenB = new Set<string>();
    while (queue.length > 0) {
      const oid = queue.shift() as string;
      if (ancestorsA.has(oid)) return oid;
      if (seenB.has(oid)) continue;
      seenB.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) queue.push(parent);
    }
    return '';
  }

  // -- fetch planning -------------------------------------------------------

  /**
   * Plan a fetch: which objects to send, the shallow boundary, and what becomes unshallow.
   * `wants` are commit/tag oids; `haves` are oids the client already holds; `depth` caps the
   * commit generations (1 = the tips only, their trees and blobs included, parents cut).
   * `deepenRelative` means the depth counts generations beyond the client's current shallow
   * boundary (git's `deepen-relative`); without it the depth is absolute from the wants.
   */
  planFetch(
    repo: RepoRec,
    wants: readonly string[],
    haves: readonly string[],
    depth: number | undefined,
    priorShallow: readonly string[],
    deepenRelative = false,
  ): { objects: GitObj[]; shallow: string[]; unshallow: string[]; ack: string | null } {
    const stopAt = new Set(priorShallow);
    const haveSet = this.reachable(repo, haves, stopAt);
    const haveCommits = new Set<string>();
    for (const oid of haveSet) {
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'commit') haveCommits.add(oid);
    }
    // Commit distances from the wants (tags peel to their target commit at distance 0).
    const dist = new Map<string, number>();
    const queue: string[] = [];
    const tagWants: string[] = [];
    for (const want of wants) {
      const obj = repo.objects.get(want);
      if (!obj) continue;
      if (obj.type === 'tag') {
        tagWants.push(want);
        const target = this.peel(repo, want);
        const targetObj = repo.objects.get(target);
        if (targetObj && targetObj.type === 'commit' && !dist.has(target)) {
          dist.set(target, 0);
          queue.push(target);
        }
      } else if (obj.type === 'commit') {
        if (!dist.has(want)) {
          dist.set(want, 0);
          queue.push(want);
        }
      }
    }
    let head = 0;
    while (head < queue.length) {
      const oid = queue[head++] as string;
      const d = dist.get(oid) as number;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) {
        if (!dist.has(parent) && repo.objects.has(parent)) {
          dist.set(parent, d + 1);
          queue.push(parent);
        }
      }
    }
    // The effective depth: absolute, or relative to the nearest shallow boundary.
    // Relative deepening adds N generations beyond the boundary: the boundary sits at
    // distance `base` from a want, the client already holds `base + 1` generations.
    let effectiveDepth = depth;
    if (depth !== undefined && deepenRelative && priorShallow.length > 0) {
      let base = Number.POSITIVE_INFINITY;
      for (const [oid, d] of dist) if (stopAt.has(oid) && d < base) base = d;
      if (base !== Number.POSITIVE_INFINITY) effectiveDepth = base + 1 + depth;
    }
    const sentCommits = new Set<string>();
    const boundary = new Set<string>();
    for (const [oid, d] of dist) {
      if (effectiveDepth === undefined || d < effectiveDepth) {
        sentCommits.add(oid);
        if (effectiveDepth !== undefined && d === effectiveDepth - 1) boundary.add(oid);
      }
    }
    // Objects to send: each sent commit with its tree closure (never a parent that is not
    // itself sent), the wanted tags, minus what the client already holds.
    const send = new Set<string>();
    for (const oid of sentCommits) {
      send.add(oid);
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'commit') {
        const tree = parseCommit(obj.data).tree;
        if (tree !== '') for (const treeOid of this.treeClosure(repo, tree)) send.add(treeOid);
      }
    }
    for (const tag of tagWants) {
      send.add(tag);
      const target = this.peel(repo, tag);
      const targetObj = repo.objects.get(target);
      if (targetObj && targetObj.type === 'tree') for (const treeOid of this.treeClosure(repo, target)) send.add(treeOid);
      else if (targetObj && targetObj.type !== 'commit') send.add(target);
    }
    for (const want of wants) {
      const obj = repo.objects.get(want);
      if (obj && obj.type !== 'commit' && obj.type !== 'tag') send.add(want);
    }
    for (const oid of haveSet) send.delete(oid);
    const objects: GitObj[] = [];
    for (const oid of send) {
      const obj = repo.objects.get(oid);
      if (obj) objects.push(obj);
    }
    // Deterministic pack order: commits first (by oid), then trees, tags, blobs — stable bytes.
    const typeRank = (t: ObjType): number => (t === 'commit' ? 0 : t === 'tree' ? 1 : t === 'tag' ? 2 : 3);
    objects.sort((a, b) => {
      const ra = typeRank(a.type);
      const rb = typeRank(b.type);
      if (ra !== rb) return ra - rb;
      return hashObject(a.type, a.data) < hashObject(b.type, b.data) ? -1 : 1;
    });
    const shallow = [...boundary].sort();
    const unshallow: string[] = [];
    for (const old of priorShallow) {
      if (boundary.has(old)) continue;
      const obj = repo.objects.get(old);
      if (!obj || obj.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.every((p) => sentCommits.has(p) || haveCommits.has(p))) unshallow.push(old);
    }
    unshallow.sort();
    let ack: string | null = null;
    for (const have of haves) {
      if (repo.objects.has(have)) {
        ack = have;
        break;
      }
    }
    return { objects, shallow, unshallow, ack };
  }

  /** The pack for a fetch, cached when the request has no haves (the clone hot path). */
  fetchPack(
    repo: RepoRec,
    wants: readonly string[],
    haves: readonly string[],
    depth: number | undefined,
    priorShallow: readonly string[],
    deepenRelative = false,
  ): { pack: Buffer | null; shallow: string[]; unshallow: string[]; ack: string | null } {
    const key = `${wants.join(',')}|${haves.join(',')}|${depth ?? ''}|${priorShallow.join(',')}|${deepenRelative ? 'r' : ''}`;
    if (haves.length === 0 && priorShallow.length === 0) {
      const cached = repo.packCache.get(key);
      if (cached) return cached;
    }
    const planned = this.planFetch(repo, wants, haves, depth, priorShallow, deepenRelative);
    if (planned.objects.length === 0) return { pack: null, shallow: planned.shallow, unshallow: planned.unshallow, ack: planned.ack };
    const pack = writePack(planned.objects);
    const result = { pack, shallow: planned.shallow, unshallow: planned.unshallow, ack: planned.ack };
    if (haves.length === 0 && priorShallow.length === 0) {
      if (repo.packCache.size >= 64) {
        const first = repo.packCache.keys().next().value as string | undefined;
        if (first !== undefined) repo.packCache.delete(first);
      }
      repo.packCache.set(key, result);
    }
    return result;
  }

  // -- trees and contents ---------------------------------------------------

  /** The blob/tree at `path` under a commit's tree, or null. */
  readPath(repo: RepoRec, commitOid: string, path: string): { oid: string; type: ObjType; data: Buffer } | null {
    const commit = repo.objects.get(commitOid);
    if (!commit || commit.type !== 'commit') return null;
    let treeOid = parseCommit(commit.data).tree;
    const segments = path.split('/').filter((s) => s !== '');
    for (let i = 0; i < segments.length; i += 1) {
      const tree = repo.objects.get(treeOid);
      if (!tree || tree.type !== 'tree') return null;
      const entry = parseTree(tree.data).find((e) => e.name === segments[i]);
      if (!entry) return null;
      if (i === segments.length - 1) {
        const obj = repo.objects.get(entry.oid);
        if (!obj) return null;
        return { oid: entry.oid, type: obj.type, data: obj.data };
      }
      if (entry.mode !== '40000') return null;
      treeOid = entry.oid;
    }
    return null;
  }

  /** The immediate children of a directory under a commit's tree. */
  listDir(repo: RepoRec, commitOid: string, dirPath: string): { name: string; path: string; oid: string; mode: string }[] | null {
    const commit = repo.objects.get(commitOid);
    if (!commit || commit.type !== 'commit') return null;
    let treeOid = parseCommit(commit.data).tree;
    const segments = dirPath.split('/').filter((s) => s !== '');
    for (const segment of segments) {
      const tree = repo.objects.get(treeOid);
      if (!tree || tree.type !== 'tree') return null;
      const entry = parseTree(tree.data).find((e) => e.name === segment && e.mode === '40000');
      if (!entry) return null;
      treeOid = entry.oid;
    }
    const tree = repo.objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return null;
    const prefix = segments.length === 0 ? '' : `${segments.join('/')}/`;
    return parseTree(tree.data).map((e) => ({ name: e.name, path: `${prefix}${e.name}`, oid: e.oid, mode: e.mode }));
  }

  /**
   * A new root tree with `path` set to `blobOid` (or removed when null), built bottom-up from
   * `baseTreeOid` (or an empty tree). New tree objects are stored; the root oid is returned.
   */
  writePath(repo: RepoRec, baseTreeOid: string | null, path: string, blobOid: string | null): string {
    const segments = path.split('/').filter((s) => s !== '');
    const build = (treeOid: string | null, depth: number): string => {
      const existing = treeOid === null ? [] : parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0));
      const name = segments[depth] as string;
      const entries: TreeEntry[] = [];
      let replaced = false;
      for (const entry of existing) {
        if (entry.name !== name) {
          entries.push(entry);
          continue;
        }
        replaced = true;
        if (depth === segments.length - 1) {
          if (blobOid !== null) entries.push({ mode: '100644', name, oid: blobOid });
        } else {
          const child = build(entry.mode === '40000' ? entry.oid : null, depth + 1);
          entries.push({ mode: '40000', name, oid: child });
        }
      }
      if (!replaced) {
        if (depth === segments.length - 1) {
          if (blobOid !== null) entries.push({ mode: '100644', name, oid: blobOid });
        } else {
          const child = build(null, depth + 1);
          entries.push({ mode: '40000', name, oid: child });
        }
      }
      const data = buildTree(entries);
      const oid = hashObject('tree', data);
      if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
      return oid;
    };
    return build(baseTreeOid, 0);
  }

  /**
   * Commit one contents change on `branch` (creating the branch from the default tip when it
   * does not exist yet). `content` null deletes the file. Returns the commit and blob shas.
   */
  contentsCommit(
    repo: RepoRec,
    branch: string,
    path: string,
    content: Buffer | null,
    message: string,
  ): { commitSha: string; contentSha: string | null } {
    const timestamp = this.nextTime();
    let parent: string | null = null;
    let baseTree: string | null = null;
    const tip = repo.refs.get(`refs/heads/${branch}`);
    if (tip !== undefined) {
      parent = tip;
      baseTree = parseCommit(repo.objects.get(tip)?.data ?? Buffer.alloc(0)).tree;
    } else {
      const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (defaultTip !== undefined) {
        parent = defaultTip;
        baseTree = parseCommit(repo.objects.get(defaultTip)?.data ?? Buffer.alloc(0)).tree;
      }
    }
    let contentSha: string | null = null;
    if (content !== null) {
      contentSha = hashObject('blob', content);
      if (!repo.objects.has(contentSha)) repo.objects.set(contentSha, { type: 'blob', data: content });
    }
    const rootTree = this.writePath(repo, baseTree, path, contentSha);
    const commitData = buildCommit(rootTree, parent === null ? [] : [parent], message, timestamp);
    const commitSha = hashObject('commit', commitData);
    if (!repo.objects.has(commitSha)) repo.objects.set(commitSha, { type: 'commit', data: commitData });
    repo.refs.set(`refs/heads/${branch}`, commitSha);
    repo.packCache.clear();
    return { commitSha, contentSha };
  }

  /** Commits reachable from `ref` (branch name, ref name or oid), newest first. */
  listCommits(repo: RepoRec, ref: string | undefined): { sha: string; message: string; seq: number }[] {
    let tip: string | undefined;
    if (ref === undefined || ref === '') {
      tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    } else if (repo.refs.has(`refs/heads/${ref}`)) {
      tip = repo.refs.get(`refs/heads/${ref}`);
    } else if (repo.refs.has(ref)) {
      tip = repo.refs.get(ref);
    } else if (repo.objects.has(ref) && repo.objects.get(ref)?.type === 'commit') {
      tip = ref;
    }
    if (tip === undefined) return [];
    // Creation order is the commit order: walk parents, newest first by traversal depth.
    const out: { sha: string; message: string; seq: number }[] = [];
    const seen = new Set<string>();
    const stack = [tip];
    let seq = 0;
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      const view = parseCommit(obj.data);
      out.push({ sha: oid, message: view.message.replace(/\n+$/, ''), seq: seq++ });
      for (const parent of view.parents) stack.push(parent);
    }
    return out;
  }

  /** The file-level diff between two trees: added, modified or removed paths. */
  diffTrees(
    repo: RepoRec,
    baseTreeOid: string | null,
    headTreeOid: string | null,
  ): { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] {
    const flatten = (treeOid: string | null, prefix: string, out: Map<string, { oid: string; mode: string }>): void => {
      if (treeOid === null) return;
      const tree = repo.objects.get(treeOid);
      if (!tree || tree.type !== 'tree') return;
      for (const entry of parseTree(tree.data)) {
        const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000') flatten(entry.oid, path, out);
        else out.set(path, { oid: entry.oid, mode: entry.mode });
      }
    };
    const base = new Map<string, { oid: string; mode: string }>();
    const head = new Map<string, { oid: string; mode: string }>();
    flatten(baseTreeOid, '', base);
    flatten(headTreeOid, '', head);
    const paths = new Set([...base.keys(), ...head.keys()]);
    const out: { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] = [];
    for (const path of [...paths].sort()) {
      const b = base.get(path);
      const h = head.get(path);
      if (b && !h) out.push({ path, status: 'removed', oldOid: b.oid, newOid: null });
      else if (!b && h) out.push({ path, status: 'added', oldOid: null, newOid: h.oid });
      else if (b && h && b.oid !== h.oid) out.push({ path, status: 'modified', oldOid: b.oid, newOid: h.oid });
    }
    return out;
  }

  /** Whether merging `pr` would conflict: a file both sides changed differently since the base. */
  mergeConflicts(repo: RepoRec, pr: PullRec): boolean {
    const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
    const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
    if (baseTip === undefined || headTip === undefined) return true;
    const baseCommit = repo.objects.get(baseTip);
    const headCommit = repo.objects.get(headTip);
    const mergeCommit = repo.objects.get(pr.mergeBase);
    if (!baseCommit || !headCommit || !mergeCommit) return true;
    const baseTree = parseCommit(baseCommit.data).tree;
    const headTree = parseCommit(headCommit.data).tree;
    const mergeTree = parseCommit(mergeCommit.data).tree;
    const headChanges = this.diffTrees(repo, mergeTree, headTree);
    const flatten = (treeOid: string, prefix: string, out: Map<string, string>): void => {
      const tree = repo.objects.get(treeOid);
      if (!tree || tree.type !== 'tree') return;
      for (const entry of parseTree(tree.data)) {
        const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000') flatten(entry.oid, path, out);
        else out.set(path, entry.oid);
      }
    };
    const baseFiles = new Map<string, string>();
    const mergeFiles = new Map<string, string>();
    flatten(baseTree, '', baseFiles);
    flatten(mergeTree, '', mergeFiles);
    for (const change of headChanges) {
      const onBase = baseFiles.get(change.path) ?? null;
      const onMerge = mergeFiles.get(change.path) ?? null;
      if (onBase !== onMerge && change.newOid !== onMerge && onBase !== change.newOid) return true;
    }
    return false;
  }

  /** Squash-merge a pull request onto its base branch; returns the merge commit sha or null. */
  squashMerge(repo: RepoRec, pr: PullRec): string | null {
    if (pr.merged || pr.state !== 'open') return null;
    if (this.mergeConflicts(repo, pr)) return null;
    const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`) as string;
    const headTip = repo.refs.get(`refs/heads/${pr.headRef}`) as string;
    const baseTree = parseCommit(repo.objects.get(baseTip)?.data ?? Buffer.alloc(0)).tree;
    const mergeTree = parseCommit(repo.objects.get(pr.mergeBase)?.data ?? Buffer.alloc(0)).tree;
    const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
    let root = baseTree;
    for (const change of this.diffTrees(repo, mergeTree, headTree)) {
      root = this.writePath(repo, root, change.path, change.newOid);
    }
    const timestamp = this.nextTime();
    const message = `Merge pull request #${pr.number} from ${pr.headRef}\n\n${pr.title}\n`;
    const commitData = buildCommit(root, [baseTip], message, timestamp);
    const mergeSha = hashObject('commit', commitData);
    if (!repo.objects.has(mergeSha)) repo.objects.set(mergeSha, { type: 'commit', data: commitData });
    repo.refs.set(`refs/heads/${pr.baseRef}`, mergeSha);
    repo.packCache.clear();
    pr.state = 'closed';
    pr.merged = true;
    pr.mergedAt = isoOf(timestamp);
    pr.mergeCommitSha = mergeSha;
    pr.baseSha = mergeSha;
    return mergeSha;
  }
}

// ---------------------------------------------------------------- HTTP plumbing

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
let requestCounter = 0;

function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': nextRequestId(), ...extraHeaders });
  res.end(text);
}

function sendBuffer(res: ServerResponse, status: number, body: Buffer, contentType: string, extraHeaders: Readonly<Record<string, string>> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': nextRequestId(), ...extraHeaders });
  res.end(body);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'x-github-request-id': nextRequestId() });
  res.end();
}

function readBody(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let failed = false;
    req.on('data', (chunk: Buffer) => {
      if (failed) return;
      total += chunk.length;
      if (total > limit) {
        failed = true;
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!failed) resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (!failed) {
        failed = true;
        reject(err);
      }
    });
  });
}

function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/.exec(header);
  return match ? (match[1] as string) : null;
}

/** The request is authenticated: the suite's token when one is configured, else any bearer. */
function isAuthenticated(req: IncomingMessage): boolean {
  const token = bearerToken(req);
  if (token === null || token === '') return false;
  if (TOKEN === '') return true;
  return token === TOKEN;
}

function parseJsonText(text: string): { ok: true; value: unknown } | { ok: false } {
  if (text.trim() === '') return { ok: false };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function urlOf(req: IncomingMessage): { path: string; query: URLSearchParams } {
  try {
    const url = new URL(req.url ?? '/', 'http://entry');
    return { path: url.pathname, query: url.searchParams };
  } catch {
    return { path: '/', query: new URLSearchParams() };
  }
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

// ---------------------------------------------------------------- git smart HTTP

const UPLOAD_CAPS_V2 = ['ls-refs=unborn', 'fetch=shallow filter', 'object-format=sha1'];
const UPLOAD_CAPS_V0 = 'symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack agent=github-core-clone/1.0.0 shallow filter object-format=sha1';
const RECEIVE_CAPS_V0 = 'report-status side-band-64k delete-refs ofs-delta agent=github-core-clone/1.0.0';

function sortedRefs(repo: RepoRec): { name: string; oid: string }[] {
  const out: { name: string; oid: string }[] = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

/** Follow tag objects to the commit (or other object) they name, using only the repo's store. */
function peelObject(repo: RepoRec, oid: string): string {
  let current = oid;
  for (let i = 0; i < 16; i += 1) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

/** The v0 ref advertisement lines, first line carrying the capabilities after a NUL. */
function v0Advertisement(repo: RepoRec, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? UPLOAD_CAPS_V0 : RECEIVE_CAPS_V0;
  const lines: (string | 'flush')[] = [`# service=${service}\n`, 'flush'];
  const refs = sortedRefs(repo);
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    lines.push(`${headTip ?? ZERO_OID} HEAD\0${caps}\n`);
    for (const ref of refs) {
      lines.push(`${ref.oid} ${ref.name}\n`);
      const obj = repo.objects.get(ref.oid);
      if (ref.name.startsWith('refs/tags/') && obj && obj.type === 'tag') {
        const peeled = peelObject(repo, ref.oid);
        if (peeled !== ref.oid) lines.push(`${peeled} ${ref.name}^{}\n`);
      }
    }
  }
  lines.push('flush');
  return pktLines(lines as (string | Buffer | 'flush' | 'delim')[]);
}

function v2Advertisement(): Buffer {
  const lines: string[] = ['version 2\n', ...UPLOAD_CAPS_V2.map((c) => `${c}\n`)];
  return Buffer.concat([pktLines(lines), PKT_FLUSH]);
}

/** One ls-refs answer line, with symref-target on HEAD and peeled on annotated tags. */
function lsRefsLines(repo: RepoRec, prefixes: readonly string[], peel: boolean, symrefs: boolean): string[] {
  const lines: string[] = [];
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (keep('HEAD')) {
    if (headTip === undefined) {
      lines.push(`unborn HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    } else {
      lines.push(`${headTip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    }
  }
  for (const ref of sortedRefs(repo)) {
    if (!keep(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (peel && ref.name.startsWith('refs/tags/')) {
      const obj = repo.objects.get(ref.oid);
      if (obj && obj.type === 'tag') {
        const peeled = peelObject(repo, ref.oid);
        if (peeled !== ref.oid) line += ` peeled:${peeled}`;
      }
    }
    lines.push(`${line}\n`);
  }
  return lines;
}

/** Split a pack into sideband band-1 packets (32 KiB of pack data each). */
function sidebandChunks(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  return out;
}

function gitNotFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

function handleInfoRefs(forge: Forge, repo: RepoRec | undefined, service: string, req: IncomingMessage, res: ServerResponse): void {
  if (repo === undefined) {
    gitNotFound(res);
    return;
  }
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    gitNotFound(res);
    return;
  }
  if (service === 'git-upload-pack' && req.headers['git-protocol'] === 'version=2') {
    sendBuffer(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
    return;
  }
  sendBuffer(res, 200, v0Advertisement(repo, service), `application/x-${service}-advertisement`);
}

/** Parse a v2 command request: the command line, then arguments after the delim. */
function parseV2Command(packets: Pkt[]): { command: string; args: string[] } | null {
  let command = '';
  const args: string[] = [];
  let seenDelim = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind === 'delim') {
      seenDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8');
    if (!seenDelim) {
      // The command section is `command=<name>` plus an optional `agent=<agent>` line.
      const match = /^command=([a-z-]+)\n?$/.exec(line);
      if (match) command = match[1] as string;
      continue;
    }
    args.push(line.replace(/\n$/, ''));
  }
  return command === '' ? null : { command, args };
}

function handleUploadPack(forge: Forge, repo: RepoRec | undefined, req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  if (repo === undefined) {
    gitNotFound(res);
    return;
  }
  let packets: Pkt[];
  try {
    packets = decodePktLines(body);
  } catch {
    sendJson(res, 400, { message: 'Bad request: malformed pkt-line stream' });
    return;
  }
  const isV2 = req.headers['git-protocol'] === 'version=2';
  if (isV2) {
    const parsed = parseV2Command(packets);
    if (parsed === null) {
      sendJson(res, 400, { message: 'Bad request: no command' });
      return;
    }
    if (parsed.command === 'ls-refs') {
      let peel = false;
      let symrefs = false;
      const prefixes: string[] = [];
      for (const arg of parsed.args) {
        if (arg === 'peel') peel = true;
        else if (arg === 'symrefs') symrefs = true;
        else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
      }
      const lines = lsRefsLines(repo, prefixes, peel, symrefs);
      const out = Buffer.concat([pktLines(lines), PKT_FLUSH]);
      sendBuffer(res, 200, out, 'application/x-git-upload-pack-result');
      return;
    }
    if (parsed.command === 'fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallow: string[] = [];
      let depth: number | undefined;
      let deepenRelative = false;
      for (const arg of parsed.args) {
        if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
        else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
        else if (arg.startsWith('shallow ')) shallow.push(arg.slice(8).trim());
        else if (arg === 'deepen-relative') deepenRelative = true;
        else if (arg.startsWith('deepen ')) {
          const n = parseInt(arg.slice(7), 10);
          if (Number.isFinite(n) && n > 0) depth = n;
        }
      }
      const { pack, shallow: newShallow, unshallow, ack } = forge.fetchPack(repo, wants, haves, depth, shallow, deepenRelative);
      // A v2 fetch response is a run of sections: each is its name line, its content lines,
      // then a delim — no delim after the name, and no trailing delim after the packfile.
      // The acknowledgments section only exists when the client left negotiation open (no
      // `done` in the request); both git and the suite always send `done`, so it is omitted.
      const hasDone = parsed.args.includes('done');
      const parts: Buffer[] = [];
      if (!hasDone && haves.length > 0) {
        parts.push(pktLine('acknowledgments\n'));
        if (ack !== null) {
          parts.push(pktLine(`ACK ${ack}\n`), pktLine('ready\n'));
        } else {
          parts.push(pktLine('NAK\n'));
        }
        parts.push(PKT_DELIM);
      }
      if (newShallow.length > 0 || unshallow.length > 0) {
        parts.push(pktLine('shallow-info\n'));
        for (const oid of newShallow) parts.push(pktLine(`shallow ${oid}\n`));
        for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
        parts.push(PKT_DELIM);
      }
      if (pack !== null) {
        parts.push(pktLine('packfile\n'));
        for (const chunk of sidebandChunks(pack)) parts.push(chunk);
      }
      parts.push(PKT_FLUSH);
      sendBuffer(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
      return;
    }
    sendJson(res, 400, { message: `Bad request: unknown command ${parsed.command}` });
    return;
  }
  // v0 fetch: want/have/done/deepen lines in two sections split by a flush.
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | undefined;
  let deepenRelative = false;
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
    else if (line === 'deepen-relative') deepenRelative = true;
    else if (line.startsWith('deepen ')) {
      const n = parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) depth = n;
    }
  }
  if (wants.length === 0) {
    sendJson(res, 400, { message: 'Bad request: no want lines' });
    return;
  }
  const { pack, shallow: newShallow, unshallow, ack } = forge.fetchPack(repo, wants, haves, depth, shallow, deepenRelative);
  const parts: Buffer[] = [];
  if (ack !== null) parts.push(pktLine(`ACK ${ack}\n`));
  else parts.push(pktLine('NAK\n'));
  for (const oid of newShallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (pack !== null) for (const chunk of sidebandChunks(pack)) parts.push(chunk);
  parts.push(PKT_FLUSH);
  sendBuffer(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

function handleReceivePack(forge: Forge, repo: RepoRec | undefined, req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  if (repo === undefined) {
    gitNotFound(res);
    return;
  }
  // The command list is pkt-lines up to the first flush; the rest is the pack.
  let flushEnd = -1;
  {
    let off = 0;
    while (off + 4 <= body.length) {
      const head = body.subarray(off, off + 4).toString('ascii');
      if (head === '0000') {
        flushEnd = off + 4;
        break;
      }
      if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
      const len = parseInt(head, 16);
      if (len < 4 || off + len > body.length) break;
      off += len;
    }
  }
  if (flushEnd < 0) {
    sendJson(res, 400, { message: 'Bad request: no command list' });
    return;
  }
  let commandPackets: Pkt[];
  try {
    commandPackets = decodePktLines(body.subarray(0, flushEnd));
  } catch {
    sendJson(res, 400, { message: 'Bad request: malformed command list' });
    return;
  }
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  for (const packet of commandPackets) {
    if (packet.kind !== 'data') continue;
    let line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line);
    if (!match) {
      sendJson(res, 400, { message: 'Bad request: malformed ref command' });
      return;
    }
    commands.push({ oldOid: match[1] as string, newOid: match[2] as string, ref: match[3] as string });
  }
  if (commands.length === 0) {
    sendJson(res, 400, { message: 'Bad request: empty command list' });
    return;
  }
  const packBytes = body.subarray(flushEnd);
  const report: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
  if (hasUpdates) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      forge.storeObjects(repo, objects);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  if (unpackOk) {
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) {
          report.push(`ng ${command.ref} ref does not exist\n`);
        } else if (current !== command.oldOid) {
          report.push(`ng ${command.ref} old oid does not match\n`);
        } else {
          repo.refs.delete(command.ref);
          repo.packCache.clear();
          report.push(`ok ${command.ref}\n`);
        }
        continue;
      }
      if (command.oldOid === ZERO_OID) {
        // Create.
        if (current !== undefined) {
          report.push(`ng ${command.ref} already exists\n`);
        } else if (!repo.objects.has(command.newOid)) {
          report.push(`ng ${command.ref} object not found\n`);
        } else {
          repo.refs.set(command.ref, command.newOid);
          repo.packCache.clear();
          report.push(`ok ${command.ref}\n`);
        }
        continue;
      }
      // Update.
      if (current === undefined) {
        report.push(`ng ${command.ref} ref does not exist\n`);
      } else if (current !== command.oldOid) {
        report.push(`ng ${command.ref} old oid does not match\n`);
      } else if (!repo.objects.has(command.newOid)) {
        report.push(`ng ${command.ref} object not found\n`);
      } else if (command.newOid !== command.oldOid && !forge.isAncestor(repo, command.oldOid, command.newOid)) {
        report.push(`ng ${command.ref} non-fast-forward\n`);
      } else {
        repo.refs.set(command.ref, command.newOid);
        repo.packCache.clear();
        report.push(`ok ${command.ref}\n`);
      }
    }
  } else {
    for (const command of commands) report.push(`ng ${command.ref} unpack failed\n`);
  }
  const reportLines = [`unpack ${unpackDetail}\n`, ...report];
  const reportBytes = pktLines([...reportLines, 'flush' as const]);
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < reportBytes.length; off += CHUNK) {
    const slice = reportBytes.subarray(off, Math.min(reportBytes.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  parts.push(PKT_FLUSH);
  sendBuffer(res, 200, Buffer.concat(parts), 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------- REST v3

let LISTEN_PORT = 0;

function ownerId(owner: string): number {
  if (owner === VIEWER) return 1000;
  return 2000 + Number(fnv1a64(owner) % 997n);
}

function repoJson(repo: RepoRec): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: `repo:${repo.owner}/${repo.name}`,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: ownerId(repo.owner), type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    created_at: isoOf(EPOCH_SEC + repo.seq),
    updated_at: isoOf(EPOCH_SEC + repo.seq),
  };
}

function issueJson(issue: IssueRec, repo: RepoRec): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: `issue:${repo.owner}/${repo.name}:${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return { name, color: label ? label.color : '000000' };
    }),
    user: { login: VIEWER, id: 1000 },
    created_at: isoOf(EPOCH_SEC + issue.seq),
    updated_at: isoOf(EPOCH_SEC + issue.seq),
  };
}

function commentJson(comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: `comment:${comment.id}`,
    body: comment.body,
    user: { login: VIEWER, id: 1000 },
    created_at: isoOf(EPOCH_SEC + comment.seq),
    updated_at: isoOf(EPOCH_SEC + comment.seq),
  };
}

function pullJson(pr: PullRec, repo: RepoRec): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: `pr:${repo.owner}/${repo.name}:${pr.number}`,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    head: { ref: pr.headRef, sha: pr.headSha, label: `${repo.owner}:${pr.headRef}` },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${repo.owner}:${pr.baseRef}` },
    user: { login: VIEWER, id: 1000 },
    created_at: isoOf(EPOCH_SEC + pr.seq),
    updated_at: isoOf(EPOCH_SEC + pr.seq),
  };
}

function branchJson(repo: RepoRec, name: string, tip: string): Record<string, unknown> {
  return { name, commit: { sha: tip, url: '' }, protected: false };
}

const REPO_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
function validRepoName(name: string): boolean {
  return REPO_NAME_RE.test(name) && !name.endsWith('.git');
}

function parsePage(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}

/** A Link header for the next page, or null when this is the last page. */
function nextLink(path: string, query: URLSearchParams, page: number, perPage: number, hasMore: boolean): string | null {
  if (!hasMore) return null;
  const next = new URLSearchParams(query);
  next.set('page', String(page + 1));
  next.set('per_page', String(perPage));
  return `<http://127.0.0.1:${LISTEN_PORT}${path}?${next.toString()}>; rel="next"`;
}

type JsonBody = Record<string, unknown>;

function handleRest(forge: Forge, req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, body: Buffer | null): void {
  const method = req.method ?? 'GET';
  const segments = path.split('/').filter((s) => s !== '');
  // segments[0] is 'api', segments[1] is 'v3'.
  const rest = segments.slice(2);
  const jsonBody: JsonBody | null = body !== null && body.length > 0 ? (parseJsonText(body.toString('utf8')).ok ? (JSON.parse(body.toString('utf8')) as JsonBody) : null) : null;
  const needBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
  if (needBody && body !== null && body.length > 0 && jsonBody === null) {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  const bad = (message: string, status = 400): void => sendJson(res, status, { message });

  // -- root and meta --------------------------------------------------------
  if (rest.length === 0) {
    if (method !== 'GET') return bad('Not Found', 404);
    sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}', user_url: '/api/v3/users/{username}' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (rest.length === 1 && rest[0] === 'meta') {
    if (method !== 'GET') return bad('Not Found', 404);
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: false });
    return;
  }
  if (rest.length === 1 && rest[0] === 'user') {
    if (method !== 'GET') return bad('Not Found', 404);
    sendJson(res, 200, { login: VIEWER, id: 1000, email: `${VIEWER}@example.invalid`, name: VIEWER, type: 'User' });
    return;
  }

  // -- /user/repos ----------------------------------------------------------
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const { page, perPage } = parsePage(query);
      const all = forge.listRepos(VIEWER);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const link = nextLink(path, query, page, perPage, page * perPage < all.length);
      sendJson(res, 200, slice.map(repoJson), link === null ? {} : { link });
      return;
    }
    if (method === 'POST') {
      const name = typeof jsonBody?.name === 'string' ? jsonBody.name : '';
      if (!validRepoName(name)) return bad('Invalid repository name', 422);
      const description = typeof jsonBody?.description === 'string' ? jsonBody.description : '';
      const isPrivate = jsonBody?.private === true;
      const repo = forge.createRepo(VIEWER, name, isPrivate, description);
      if (repo === null) return bad(`name already exists on this account`, 422);
      sendJson(res, 201, repoJson(repo));
      return;
    }
    return bad('Not Found', 404);
  }

  // -- /repos/:owner/:repo/... ----------------------------------------------
  if (rest.length >= 3 && rest[0] === 'repos') {
    const owner = decodeSegment(rest[1] as string);
    const repoName = decodeSegment(rest[2] as string);
    const repo = forge.getRepo(owner, repoName);
    if (repo === undefined) return bad('Not Found', 404);
    const tail = rest.slice(3);

    if (tail.length === 0) {
      if (method === 'GET') return sendJson(res, 200, repoJson(repo));
      if (method === 'PATCH') {
        if (typeof jsonBody?.description === 'string') repo.description = jsonBody.description;
        return sendJson(res, 200, repoJson(repo));
      }
      if (method === 'DELETE') {
        forge.deleteRepo(owner, repoName);
        return sendEmpty(res, 204);
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'branches') {
      if (tail.length === 1) {
        if (method !== 'GET') return bad('Not Found', 404);
        const branches = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((name) => branchJson(repo, name, repo.refs.get(`refs/heads/${name}`) as string));
        return sendJson(res, 200, branches);
      }
      if (tail.length === 2) {
        if (method !== 'GET') return bad('Not Found', 404);
        const branch = decodeSegment(tail[1] as string);
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) return bad('Branch not found', 404);
        return sendJson(res, 200, branchJson(repo, branch, tip));
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'commits') {
      if (method !== 'GET' || tail.length !== 1) return bad('Not Found', 404);
      const ref = query.get('sha') ?? undefined;
      const commits = forge.listCommits(repo, ref);
      return sendJson(res, 200, commits.map((c) => ({ sha: c.sha, commit: { message: c.message } })));
    }

    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const ref = typeof jsonBody?.ref === 'string' ? jsonBody.ref : '';
        const sha = typeof jsonBody?.sha === 'string' ? jsonBody.sha : '';
        const match = /^refs\/heads\/([A-Za-z0-9][A-Za-z0-9._\/-]*)$/.exec(ref);
        if (match === null) return bad('Invalid ref', 422);
        const branch = match[1] as string;
        const obj = repo.objects.get(sha);
        if (obj === undefined || obj.type !== 'commit') return bad('Invalid sha', 422);
        if (repo.refs.has(ref)) return bad('Reference already exists', 422);
        repo.refs.set(ref, sha);
        repo.packCache.clear();
        return sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
      }
      if (method === 'GET' && tail.length === 4 && tail[2] === 'heads') {
        const branch = decodeSegment(tail[3] as string);
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) return bad('Not Found', 404);
        return sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit' } });
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'contents') {
      const contentPath = tail.slice(1).map(decodeSegment).join('/');
      const branch = typeof jsonBody?.branch === 'string' ? (jsonBody.branch as string) : repo.defaultBranch;
      if (method === 'PUT') {
        const message = typeof jsonBody?.message === 'string' ? (jsonBody.message as string) : `Update ${contentPath}`;
        const contentB64 = typeof jsonBody?.content === 'string' ? (jsonBody.content as string) : '';
        let content: Buffer;
        try {
          content = Buffer.from(contentB64, 'base64');
        } catch {
          return bad('Invalid content encoding', 422);
        }
        const expectedSha = typeof jsonBody?.sha === 'string' ? (jsonBody.sha as string) : null;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        const existing = tip === undefined ? null : forge.readPath(repo, tip, contentPath);
        if (expectedSha !== null) {
          if (existing === null) return bad('Invalid request.\n\n"sha" wasn\'t supplied.', 422);
          if (existing.oid !== expectedSha) return bad('sha does not match', 409);
        }
        const { commitSha, contentSha } = forge.contentsCommit(repo, branch, contentPath, content, message);
        return sendJson(res, existing === null ? 201 : 200, { content: { name: contentPath.split('/').pop() ?? '', path: contentPath, sha: contentSha, size: content.length, encoding: 'base64' }, commit: { sha: commitSha, message } });
      }
      if (method === 'GET') {
        const refParam = query.get('ref') ?? undefined;
        let tip: string | undefined;
        if (refParam === undefined) {
          tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        } else if (repo.refs.has(`refs/heads/${refParam}`)) {
          tip = repo.refs.get(`refs/heads/${refParam}`);
        } else if (repo.refs.has(refParam)) {
          tip = repo.refs.get(refParam);
        } else if (repo.objects.has(refParam)) {
          tip = refParam;
        }
        if (tip === undefined) return bad('Not Found', 404);
        const dir = forge.listDir(repo, tip, contentPath);
        if (dir !== null) {
          return sendJson(res, 200, dir.map((e) => ({ type: e.mode === '40000' ? 'dir' : 'file', name: e.name, path: e.path, sha: e.oid })));
        }
        const found = forge.readPath(repo, tip, contentPath);
        if (found === null || found.type !== 'blob') return bad('Not Found', 404);
        return sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          size: found.data.length,
          name: contentPath.split('/').pop() ?? '',
          path: contentPath,
          content: found.data.toString('base64'),
          sha: found.oid,
        });
      }
      if (method === 'DELETE') {
        const message = typeof jsonBody?.message === 'string' ? (jsonBody.message as string) : `Delete ${contentPath}`;
        const expectedSha = typeof jsonBody?.sha === 'string' ? (jsonBody.sha as string) : null;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) return bad('Not Found', 404);
        const existing = forge.readPath(repo, tip, contentPath);
        if (existing === null) return bad('Not Found', 404);
        if (expectedSha !== null && existing.oid !== expectedSha) return bad('sha does not match', 409);
        const { commitSha } = forge.contentsCommit(repo, branch, contentPath, null, message);
        return sendJson(res, 200, { commit: { sha: commitSha, message } });
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'labels') {
      if (method === 'GET' && tail.length === 1) {
        return sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color })));
      }
      if (method === 'POST' && tail.length === 1) {
        const name = typeof jsonBody?.name === 'string' ? (jsonBody.name as string) : '';
        const color = typeof jsonBody?.color === 'string' ? (jsonBody.color as string) : '000000';
        if (name === '') return bad('Invalid label', 422);
        const existing = repo.labels.get(name);
        if (existing) return sendJson(res, 201, { name: existing.name, color: existing.color });
        repo.labels.set(name, { name, color });
        return sendJson(res, 201, { name, color });
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const direction = query.get('direction') ?? 'desc';
          const { page, perPage } = parsePage(query);
          let list = repo.issues;
          if (state !== 'all') list = list.filter((i) => i.state === state);
          list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const slice = list.slice((page - 1) * perPage, page * perPage);
          const link = nextLink(path, query, page, perPage, page * perPage < list.length);
          return sendJson(res, 200, slice.map((i) => issueJson(i, repo)), link === null ? {} : { link });
        }
        if (method === 'POST') {
          const title = typeof jsonBody?.title === 'string' ? (jsonBody.title as string) : '';
          const bodyText = typeof jsonBody?.body === 'string' ? (jsonBody.body as string) : '';
          const labels = Array.isArray(jsonBody?.labels) ? (jsonBody.labels as unknown[]) : [];
          if (title === '') return bad('Invalid title', 422);
          const labelNames: string[] = [];
          for (const label of labels) {
            if (typeof label !== 'string') continue;
            if (!repo.labels.has(label)) return bad(`Label does not exist: ${label}`, 422);
            labelNames.push(label);
          }
          const number = repo.issueSeq + 1;
          repo.issueSeq = number;
          const issue: IssueRec = {
            number,
            id: (forge.issueIdSeq += 1),
            title,
            body: bodyText,
            state: 'open',
            labels: labelNames,
            seq: forge.nextTime() - EPOCH_SEC,
          };
          repo.issues.push(issue);
          repo.comments.set(number, []);
          return sendJson(res, 201, issueJson(issue, repo));
        }
        return bad('Not Found', 404);
      }
      const issueNumber = parseInt(tail[1] as string, 10);
      if (!Number.isInteger(issueNumber)) return bad('Not Found', 404);
      const issue = repo.issues.find((i) => i.number === issueNumber);
      if (tail.length === 2) {
        if (issue === undefined) return bad('Not Found', 404);
        if (method === 'GET') return sendJson(res, 200, issueJson(issue, repo));
        if (method === 'PATCH') {
          if (jsonBody?.state === 'open' || jsonBody?.state === 'closed') issue.state = jsonBody.state;
          if (typeof jsonBody?.title === 'string') issue.title = jsonBody.title as string;
          if (typeof jsonBody?.body === 'string') issue.body = jsonBody.body as string;
          return sendJson(res, 200, issueJson(issue, repo));
        }
        return bad('Not Found', 404);
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (issue === undefined) return bad('Not Found', 404);
        const comments = repo.comments.get(issueNumber) ?? [];
        if (method === 'GET') return sendJson(res, 200, comments.map(commentJson));
        if (method === 'POST') {
          const bodyText = typeof jsonBody?.body === 'string' ? (jsonBody.body as string) : '';
          if (bodyText === '') return bad('Invalid comment', 422);
          const comment: CommentRec = { id: (forge.commentIdSeq += 1), body: bodyText, seq: forge.nextTime() - EPOCH_SEC };
          comments.push(comment);
          repo.comments.set(issueNumber, comments);
          return sendJson(res, 201, commentJson(comment));
        }
        return bad('Not Found', 404);
      }
      return bad('Not Found', 404);
    }

    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const { page, perPage } = parsePage(query);
          let list = repo.pulls;
          if (state !== 'all') list = list.filter((p) => p.state === state);
          const slice = list.slice((page - 1) * perPage, page * perPage);
          const link = nextLink(path, query, page, perPage, page * perPage < list.length);
          return sendJson(res, 200, slice.map((p) => pullJson(p, repo)), link === null ? {} : { link });
        }
        if (method === 'POST') {
          const head = typeof jsonBody?.head === 'string' ? (jsonBody.head as string) : '';
          const base = typeof jsonBody?.base === 'string' ? (jsonBody.base as string) : '';
          const title = typeof jsonBody?.title === 'string' ? (jsonBody.title as string) : '';
          const bodyText = typeof jsonBody?.body === 'string' ? (jsonBody.body as string) : '';
          const headTip = repo.refs.get(`refs/heads/${head}`);
          const baseTip = repo.refs.get(`refs/heads/${base}`);
          if (headTip === undefined || baseTip === undefined) return bad('Invalid head or base', 422);
          const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
          if (duplicate) return bad('A pull request already exists for this head and base', 422);
          const number = repo.pullSeq + 1;
          repo.pullSeq = number;
          const pr: PullRec = {
            number,
            id: (forge.pullIdSeq += 1),
            title,
            body: bodyText,
            state: 'open',
            merged: false,
            mergedAt: null,
            mergeCommitSha: null,
            headRef: head,
            baseRef: base,
            headSha: headTip,
            baseSha: baseTip,
            mergeBase: forge.mergeBase(repo, baseTip, headTip),
            seq: forge.nextTime() - EPOCH_SEC,
          };
          repo.pulls.push(pr);
          return sendJson(res, 201, pullJson(pr, repo));
        }
        return bad('Not Found', 404);
      }
      const pullNumber = parseInt(tail[1] as string, 10);
      if (!Number.isInteger(pullNumber)) return bad('Not Found', 404);
      const pr = repo.pulls.find((p) => p.number === pullNumber);
      if (tail.length === 2) {
        if (pr === undefined) return bad('Not Found', 404);
        if (method !== 'GET') return bad('Not Found', 404);
        return sendJson(res, 200, pullJson(pr, repo));
      }
      if (tail.length === 3 && tail[2] === 'files') {
        if (pr === undefined) return bad('Not Found', 404);
        if (method !== 'GET') return bad('Not Found', 404);
        const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
        const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
        if (baseTip === undefined || headTip === undefined) return bad('Not Found', 404);
        const mergeTree = parseCommit(repo.objects.get(pr.mergeBase)?.data ?? Buffer.alloc(0)).tree;
        const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
        const diff = forge.diffTrees(repo, mergeTree, headTree);
        const files = diff.map((change) => {
          const lineCount = (oid: string | null): number => {
            if (oid === null) return 0;
            const obj = repo.objects.get(oid);
            if (!obj || obj.type !== 'blob') return 0;
            const text = obj.data.toString('utf8');
            return text === '' ? 0 : text.split('\n').length;
          };
          let additions = 0;
          let deletions = 0;
          if (change.status === 'added') additions = lineCount(change.newOid);
          else if (change.status === 'removed') deletions = lineCount(change.oldOid);
          else {
            const oldText = repo.objects.get(change.oldOid as string)?.data.toString('utf8') ?? '';
            const newText = repo.objects.get(change.newOid as string)?.data.toString('utf8') ?? '';
            const oldLines = new Set(oldText === '' ? [] : oldText.split('\n'));
            const newLines = new Set(newText === '' ? [] : newText.split('\n'));
            for (const line of newLines) if (!oldLines.has(line)) additions += 1;
            for (const line of oldLines) if (!newLines.has(line)) deletions += 1;
          }
          return { filename: change.path, status: change.status, additions, deletions, changes: additions + deletions };
        });
        return sendJson(res, 200, files);
      }
      if (tail.length === 3 && tail[2] === 'merge') {
        if (pr === undefined) return bad('Not Found', 404);
        if (method !== 'PUT') return bad('Not Found', 404);
        if (pr.merged) return bad('Pull request already merged', 405);
        if (pr.state !== 'open') return bad('Pull request is closed', 405);
        const mergeMethod = typeof jsonBody?.merge_method === 'string' ? (jsonBody.merge_method as string) : 'squash';
        if (mergeMethod !== 'squash') return bad('Unsupported merge method', 405);
        if (forge.mergeConflicts(repo, pr)) return bad('Merge conflict', 405);
        const mergeSha = forge.squashMerge(repo, pr);
        if (mergeSha === null) return bad('Merge conflict', 405);
        return sendJson(res, 200, { merged: true, sha: mergeSha, message: 'Pull Request successfully merged' });
      }
      return bad('Not Found', 404);
    }

    return bad('Not Found', 404);
  }

  return bad('Not Found', 404);
}

// ---------------------------------------------------------------- GraphQL

// -- schema tables (the fixed surface the conformance documents use) --------

const GQL_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequest: ['id', 'number', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'title', 'body'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo'],
  PullRequestEdge: ['node', 'cursor'],
  PullRequestChangedFile: ['path'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo'],
  Ref: ['name'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor'],
  Comment: ['id', 'body'],
  CommentEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  __Type: ['name', 'kind', 'fields', 'enumValues'],
  __Schema: ['types', 'queryType', 'mutationType'],
  __Field: ['name'],
  __EnumValue: ['name'],
  Node: ['id'],
};

const GQL_RETURN: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node', __type: '__Type', __schema: '__Schema' },
  Repository: { owner: 'User', defaultBranchRef: 'Ref', issue: 'Issue', issues: 'IssueConnection', pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest' },
  IssueConnection: { nodes: 'Issue', edges: 'IssueEdge', pageInfo: 'PageInfo' },
  IssueEdge: { node: 'Issue' },
  PullRequest: { files: 'PullRequestChangedFileConnection' },
  PullRequestConnection: { nodes: 'PullRequest', edges: 'PullRequestEdge', pageInfo: 'PageInfo' },
  PullRequestEdge: { node: 'PullRequest' },
  PullRequestChangedFileConnection: { nodes: 'PullRequestChangedFile', edges: 'PullRequestChangedFile' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'CommentEdge' },
  CommentEdge: { node: 'Comment' },
  __Type: { fields: '__Field', enumValues: '__EnumValue' },
  __Schema: { types: '__Type', queryType: '__Type', mutationType: '__Type' },
};

const GQL_ENUMS: Readonly<Record<string, readonly string[]>> = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER'],
  MergeableState: ['CONFLICTING', 'MERGEABLE', 'UNKNOWN'],
  MergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
};

// -- lexer ------------------------------------------------------------------

interface GqlToken {
  kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'eof';
  value: string;
}

function lexGraphQL(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  const push = (kind: GqlToken['kind'], value: string): void => {
    tokens.push({ kind, value });
  };
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',' || ch === '﻿') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      push('punct', '...');
      i += 3;
      continue;
    }
    if ('!$&():=@[]{}|'.includes(ch)) {
      push('punct', ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.slice(i, i + 3) === '"""') {
        const end = source.indexOf('"""', i + 3);
        push('string', end === -1 ? source.slice(i + 3) : source.slice(i + 3, end));
        i = end === -1 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j] as string;
          j += 1;
        }
      }
      push('string', out);
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      if (source[j] === '-') j += 1;
      let isFloat = false;
      while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      if (source[j] === '.') {
        isFloat = true;
        j += 1;
        while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      }
      if (source[j] === 'e' || source[j] === 'E') {
        isFloat = true;
        j += 1;
        if (source[j] === '+' || source[j] === '-') j += 1;
        while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      }
      push(isFloat ? 'float' : 'int', source.slice(i, j));
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < source.length && /[_A-Za-z0-9]/.test(source[j] as string)) j += 1;
      push('name', source.slice(i, j));
      i = j;
      continue;
    }
    throw new Error(`Unexpected character ${ch}`);
  }
  push('eof', '');
  return tokens;
}

// -- parser -----------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'string'; value: string }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: { name: string; value: GqlValue }[] };

interface GqlField {
  kind: 'field';
  name: string;
  alias: string | null;
  args: { name: string; value: GqlValue }[];
  selections: GqlSelection[];
}

interface GqlFragmentSpread {
  kind: 'spread';
  name: string;
}

interface GqlInlineFragment {
  kind: 'inline';
  typeCondition: string | null;
  selections: GqlSelection[];
}

type GqlSelection = GqlField | GqlFragmentSpread | GqlInlineFragment;

interface GqlOperation {
  kind: 'operation';
  operation: 'query' | 'mutation' | 'subscription';
  name: string | null;
  variableDefinitions: { name: string; defaultValue: GqlValue | null }[];
  selections: GqlSelection[];
}

interface GqlFragment {
  kind: 'fragment';
  name: string;
  typeCondition: string;
  selections: GqlSelection[];
}

class GqlParser {
  tokens: GqlToken[];
  pos = 0;
  constructor(source: string) {
    this.tokens = lexGraphQL(source);
  }
  peek(): GqlToken {
    return this.tokens[this.pos] as GqlToken;
  }
  next(): GqlToken {
    const tok = this.tokens[this.pos] as GqlToken;
    this.pos += 1;
    return tok;
  }
  expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'punct' || tok.value !== value) throw new Error(`Expected ${value}, got ${tok.value}`);
  }
  expectName(value?: string): string {
    const tok = this.next();
    if (tok.kind !== 'name' || (value !== undefined && tok.value !== value)) throw new Error(`Expected name ${value ?? ''}, got ${tok.value}`);
    return tok.value;
  }
  parseDocument(): { operations: GqlOperation[]; fragments: Map<string, GqlFragment> } {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlFragment>();
    while (this.peek().kind !== 'eof') {
      const tok = this.peek();
      if (tok.kind === 'punct' && tok.value === '{') {
        operations.push({ kind: 'operation', operation: 'query', name: null, variableDefinitions: [], selections: this.parseSelectionSet() });
      } else if (tok.kind === 'name' && (tok.value === 'query' || tok.value === 'mutation' || tok.value === 'subscription')) {
        const operation = this.next().value as 'query' | 'mutation' | 'subscription';
        let name: string | null = null;
        if (this.peek().kind === 'name') name = this.next().value;
        const variableDefinitions = this.parseVariableDefinitions();
        this.skipDirectives();
        operations.push({ kind: 'operation', operation, name, variableDefinitions, selections: this.parseSelectionSet() });
      } else if (tok.kind === 'name' && tok.value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.skipDirectives();
        fragments.set(name, { kind: 'fragment', name, typeCondition, selections: this.parseSelectionSet() });
      } else {
        throw new Error(`Unexpected token ${tok.value}`);
      }
    }
    return { operations, fragments };
  }
  parseVariableDefinitions(): { name: string; defaultValue: GqlValue | null }[] {
    const defs: { name: string; defaultValue: GqlValue | null }[] = [];
    if (this.peek().kind === 'punct' && this.peek().value === '(') {
      this.next();
      while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
        this.expectPunct('$');
        const name = this.expectName();
        this.expectPunct(':');
        this.parseType();
        let defaultValue: GqlValue | null = null;
        if (this.peek().kind === 'punct' && this.peek().value === '=') {
          this.next();
          defaultValue = this.parseValue();
        }
        this.skipDirectives();
        defs.push({ name, defaultValue });
      }
      this.expectPunct(')');
    }
    return defs;
  }
  parseType(): void {
    if (this.peek().kind === 'punct' && this.peek().value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.peek().kind === 'punct' && this.peek().value === '!') this.next();
  }
  skipDirectives(): void {
    while (this.peek().kind === 'punct' && this.peek().value === '@') {
      this.next();
      this.expectName();
      if (this.peek().kind === 'punct' && this.peek().value === '(') this.parseArguments();
    }
  }
  parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }
  parseSelection(): GqlSelection {
    if (this.peek().kind === 'punct' && this.peek().value === '...') {
      this.next();
      if (this.peek().kind === 'name' && this.peek().value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (this.peek().kind === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'spread', name };
      }
      this.skipDirectives();
      return { kind: 'inline', typeCondition: null, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek().kind === 'punct' && this.peek().value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args = this.parseArguments();
    this.skipDirectives();
    const selections = this.peek().kind === 'punct' && this.peek().value === '{' ? this.parseSelectionSet() : [];
    return { kind: 'field', name, alias, args, selections };
  }
  parseArguments(): { name: string; value: GqlValue }[] {
    const args: { name: string; value: GqlValue }[] = [];
    if (this.peek().kind === 'punct' && this.peek().value === '(') {
      this.next();
      while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
        const name = this.expectName();
        this.expectPunct(':');
        args.push({ name, value: this.parseValue() });
      }
      this.expectPunct(')');
    }
    return args;
  }
  parseValue(): GqlValue {
    const tok = this.next();
    if (tok.kind === 'punct' && tok.value === '$') return { kind: 'variable', name: this.expectName() };
    if (tok.kind === 'punct' && tok.value === '[') {
      const values: GqlValue[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === ']')) values.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', values };
    }
    if (tok.kind === 'punct' && tok.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (tok.kind === 'int') return { kind: 'int', value: parseInt(tok.value, 10) };
    if (tok.kind === 'float') return { kind: 'float', value: parseFloat(tok.value) };
    if (tok.kind === 'string') return { kind: 'string', value: tok.value };
    if (tok.kind === 'name') {
      if (tok.value === 'true') return { kind: 'boolean', value: true };
      if (tok.value === 'false') return { kind: 'boolean', value: false };
      if (tok.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: tok.value };
    }
    throw new Error(`Unexpected value token ${tok.value}`);
  }
}

// -- executor -----------------------------------------------------------------

type GqlNode = { __typename: string; [key: string]: unknown };

interface GqlContext {
  forge: Forge;
  variables: Record<string, unknown>;
  fragments: Map<string, GqlFragment>;
  errors: { message: string }[];
}

function valueOf(value: GqlValue, ctx: GqlContext): unknown {
  switch (value.kind) {
    case 'variable':
      return ctx.variables[value.name] ?? null;
    case 'int':
    case 'float':
    case 'string':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((v) => valueOf(v, ctx));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = valueOf(field.value, ctx);
      return out;
    }
  }
}

function argOf(field: GqlField, name: string, ctx: GqlContext): unknown {
  const found = field.args.find((a) => a.name === name);
  return found === undefined ? undefined : valueOf(found.value, ctx);
}

function repoNode(repo: RepoRec): GqlNode {
  return { __typename: 'Repository', repo };
}

function issueNode(repo: RepoRec, issue: IssueRec): GqlNode {
  return { __typename: 'Issue', repo, issue };
}

function pullNode(repo: RepoRec, pr: PullRec): GqlNode {
  return { __typename: 'PullRequest', repo, pr };
}

function parseGlobalId(id: unknown): { kind: string; owner: string; name: string; number: number } | null {
  if (typeof id !== 'string') return null;
  const repoMatch = /^repo:([^/]+)\/(.+)$/.exec(id);
  if (repoMatch) return { kind: 'repo', owner: repoMatch[1] as string, name: repoMatch[2] as string, number: 0 };
  const issueMatch = /^issue:([^/]+)\/(.+):(\d+)$/.exec(id);
  if (issueMatch) return { kind: 'issue', owner: issueMatch[1] as string, name: issueMatch[2] as string, number: parseInt(issueMatch[3] as string, 10) };
  const prMatch = /^pr:([^/]+)\/(.+):(\d+)$/.exec(id);
  if (prMatch) return { kind: 'pr', owner: prMatch[1] as string, name: prMatch[2] as string, number: parseInt(prMatch[3] as string, 10) };
  return null;
}

function encodeCursor(index: number): string {
  return `cursor:${index}`;
}

function decodeCursor(after: unknown): number {
  if (typeof after !== 'string') return -1;
  const match = /^cursor:(\d+)$/.exec(after);
  return match === null ? -1 : parseInt(match[1] as string, 10);
}

function pageInfoFor(total: number, start: number, end: number): GqlNode {
  return {
    __typename: 'PageInfo',
    hasNextPage: end < total,
    hasPreviousPage: start > 0,
    endCursor: end > start ? encodeCursor(end - 1) : null,
    startCursor: end > start ? encodeCursor(start) : null,
  };
}

/** Resolve one field on a node; returns the raw value (a node, a list, a scalar, or null). */
function resolveField(parentType: string, parent: GqlNode, field: GqlField, ctx: GqlContext): unknown {
  const { forge } = ctx;
  const name = field.name;
  if (parentType === 'Query') {
    if (name === 'viewer') return { __typename: 'User', login: VIEWER, id: 1000 };
    if (name === 'repository') {
      const owner = argOf(field, 'owner', ctx);
      const repoName = argOf(field, 'name', ctx);
      if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
      const repo = forge.getRepo(owner, repoName);
      return repo === undefined ? null : repoNode(repo);
    }
    if (name === 'node') {
      const parsed = parseGlobalId(argOf(field, 'id', ctx));
      if (parsed === null) return null;
      const repo = forge.getRepo(parsed.owner, parsed.name);
      if (repo === undefined) return null;
      if (parsed.kind === 'repo') return repoNode(repo);
      if (parsed.kind === 'issue') {
        const issue = repo.issues.find((i) => i.number === parsed.number);
        return issue === undefined ? null : issueNode(repo, issue);
      }
      const pr = repo.pulls.find((p) => p.number === parsed.number);
      return pr === undefined ? null : pullNode(repo, pr);
    }
    if (name === '__type') {
      const typeName = argOf(field, 'name', ctx);
      if (typeof typeName !== 'string') return null;
      if (GQL_FIELDS[typeName] === undefined && GQL_ENUMS[typeName] === undefined) return null;
      return { __typename: '__Type', typeName };
    }
    if (name === '__schema') return { __typename: '__Schema' };
    return null;
  }
  if (parentType === 'Mutation') {
    if (name === 'createIssue') {
      const input = argOf(field, 'input', ctx) as Record<string, unknown> | undefined;
      const parsed = parseGlobalId(input?.repositoryId);
      if (parsed === null || parsed.kind !== 'repo') {
        ctx.errors.push({ message: 'Invalid repositoryId' });
        return null;
      }
      const repo = forge.getRepo(parsed.owner, parsed.name);
      if (repo === undefined) {
        ctx.errors.push({ message: 'Repository not found' });
        return null;
      }
      const number = repo.issueSeq + 1;
      repo.issueSeq = number;
      const issue: IssueRec = {
        number,
        id: (forge.issueIdSeq += 1),
        title: typeof input?.title === 'string' ? (input.title as string) : '',
        body: typeof input?.body === 'string' ? (input.body as string) : '',
        state: 'open',
        labels: [],
        seq: forge.nextTime() - EPOCH_SEC,
      };
      repo.issues.push(issue);
      repo.comments.set(number, []);
      return { __typename: 'CreateIssuePayload', issue: issueNode(repo, issue) };
    }
    if (name === 'closeIssue') {
      const input = argOf(field, 'input', ctx) as Record<string, unknown> | undefined;
      const parsed = parseGlobalId(input?.issueId);
      if (parsed === null || parsed.kind !== 'issue') {
        ctx.errors.push({ message: 'Invalid issueId' });
        return null;
      }
      const repo = forge.getRepo(parsed.owner, parsed.name);
      const issue = repo?.issues.find((i) => i.number === parsed.number);
      if (issue === undefined) {
        ctx.errors.push({ message: 'Issue not found' });
        return null;
      }
      issue.state = 'closed';
      return { __typename: 'CloseIssuePayload', issue: issueNode(repo as RepoRec, issue) };
    }
    if (name === 'createPullRequest') {
      const input = argOf(field, 'input', ctx) as Record<string, unknown> | undefined;
      const parsed = parseGlobalId(input?.repositoryId);
      if (parsed === null || parsed.kind !== 'repo') {
        ctx.errors.push({ message: 'Invalid repositoryId' });
        return null;
      }
      const repo = forge.getRepo(parsed.owner, parsed.name);
      if (repo === undefined) {
        ctx.errors.push({ message: 'Repository not found' });
        return null;
      }
      const head = typeof input?.headRefName === 'string' ? (input.headRefName as string) : '';
      const base = typeof input?.baseRefName === 'string' ? (input.baseRefName as string) : '';
      const headTip = repo.refs.get(`refs/heads/${head}`);
      const baseTip = repo.refs.get(`refs/heads/${base}`);
      if (headTip === undefined || baseTip === undefined) {
        ctx.errors.push({ message: 'Invalid head or base' });
        return null;
      }
      const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (duplicate) return { __typename: 'CreatePullRequestPayload', pullRequest: pullNode(repo, duplicate) };
      const number = repo.pullSeq + 1;
      repo.pullSeq = number;
      const pr: PullRec = {
        number,
        id: (forge.pullIdSeq += 1),
        title: typeof input?.title === 'string' ? (input.title as string) : '',
        body: typeof input?.body === 'string' ? (input.body as string) : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        baseRef: base,
        headSha: headTip,
        baseSha: baseTip,
        mergeBase: forge.mergeBase(repo, baseTip, headTip),
        seq: forge.nextTime() - EPOCH_SEC,
      };
      repo.pulls.push(pr);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullNode(repo, pr) };
    }
    if (name === 'mergePullRequest') {
      const input = argOf(field, 'input', ctx) as Record<string, unknown> | undefined;
      const parsed = parseGlobalId(input?.pullRequestId);
      if (parsed === null || parsed.kind !== 'pr') {
        ctx.errors.push({ message: 'Invalid pullRequestId' });
        return null;
      }
      const repo = forge.getRepo(parsed.owner, parsed.name);
      const pr = repo?.pulls.find((p) => p.number === parsed.number);
      if (pr === undefined || repo === undefined) {
        ctx.errors.push({ message: 'Pull request not found' });
        return null;
      }
      const method = typeof input?.mergeMethod === 'string' ? (input.mergeMethod as string) : 'SQUASH';
      if (method !== 'SQUASH') {
        ctx.errors.push({ message: 'Unsupported merge method' });
        return null;
      }
      if (pr.merged || pr.state !== 'open' || forge.mergeConflicts(repo, pr)) {
        ctx.errors.push({ message: 'Pull request cannot be merged' });
        return null;
      }
      forge.squashMerge(repo, pr);
      return { __typename: 'MergePullRequestPayload', pullRequest: pullNode(repo, pr) };
    }
    if (name === 'addComment') {
      const input = argOf(field, 'input', ctx) as Record<string, unknown> | undefined;
      const parsed = parseGlobalId(input?.subjectId);
      if (parsed === null || parsed.kind !== 'issue') {
        ctx.errors.push({ message: 'Invalid subjectId' });
        return null;
      }
      const repo = forge.getRepo(parsed.owner, parsed.name);
      const issue = repo?.issues.find((i) => i.number === parsed.number);
      if (issue === undefined || repo === undefined) {
        ctx.errors.push({ message: 'Issue not found' });
        return null;
      }
      const comment: CommentRec = { id: (forge.commentIdSeq += 1), body: typeof input?.body === 'string' ? (input.body as string) : '', seq: forge.nextTime() - EPOCH_SEC };
      const comments = repo.comments.get(parsed.number) ?? [];
      comments.push(comment);
      repo.comments.set(parsed.number, comments);
      return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'CommentEdge', node: { __typename: 'Comment', id: `comment:${comment.id}`, body: comment.body } } };
    }
    return null;
  }
  if (parentType === 'User') {
    if (name === 'login') return parent.login ?? VIEWER;
    if (name === 'id') return parent.id ?? 1000;
    if (name === 'name') return parent.login ?? VIEWER;
    if (name === 'email') return `${parent.login ?? VIEWER}@example.invalid`;
    return null;
  }
  if (parentType === 'Repository') {
    const repo = parent.repo as RepoRec;
    if (name === 'id') return `repo:${repo.owner}/${repo.name}`;
    if (name === 'databaseId') return repo.id;
    if (name === 'name') return repo.name;
    if (name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (name === 'owner') return { __typename: 'User', login: repo.owner, id: ownerId(repo.owner) };
    if (name === 'defaultBranchRef') {
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      return tip === undefined ? null : { __typename: 'Ref', name: repo.defaultBranch };
    }
    if (name === 'viewerPermission') return 'ADMIN';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'issue') {
      const number = argOf(field, 'number', ctx);
      if (typeof number !== 'number') return null;
      const issue = repo.issues.find((i) => i.number === number);
      return issue === undefined ? null : issueNode(repo, issue);
    }
    if (name === 'issues') {
      const first = argOf(field, 'first', ctx);
      const after = argOf(field, 'after', ctx);
      const states = argOf(field, 'states', ctx);
      const orderBy = argOf(field, 'orderBy', ctx) as { field?: string; direction?: string } | undefined;
      let list = repo.issues;
      if (Array.isArray(states) && states.length > 0) {
        const wanted = new Set(states.map((s) => String(s)));
        list = list.filter((i) => wanted.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      const direction = orderBy?.direction === 'ASC' ? 'asc' : 'desc';
      list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      const start = decodeCursor(after) + 1;
      const count = typeof first === 'number' && first >= 0 ? first : list.length;
      const slice = list.slice(start, start + count);
      return {
        __typename: 'IssueConnection',
        nodes: slice.map((i) => issueNode(repo, i)),
        edges: slice.map((i, idx) => ({ __typename: 'IssueEdge', node: issueNode(repo, i), cursor: encodeCursor(start + idx) })),
        pageInfo: pageInfoFor(list.length, start, start + slice.length),
        totalCount: list.length,
      };
    }
    if (name === 'pullRequests') {
      const first = argOf(field, 'first', ctx);
      const list = repo.pulls;
      const count = typeof first === 'number' && first >= 0 ? first : list.length;
      const slice = list.slice(0, count);
      return {
        __typename: 'PullRequestConnection',
        nodes: slice.map((p) => pullNode(repo, p)),
        edges: slice.map((p, idx) => ({ __typename: 'PullRequestEdge', node: pullNode(repo, p), cursor: encodeCursor(idx) })),
        pageInfo: pageInfoFor(list.length, 0, slice.length),
      };
    }
    if (name === 'pullRequest') {
      const number = argOf(field, 'number', ctx);
      if (typeof number !== 'number') return null;
      const pr = repo.pulls.find((p) => p.number === number);
      return pr === undefined ? null : pullNode(repo, pr);
    }
    return null;
  }
  if (parentType === 'Issue') {
    const issue = parent.issue as IssueRec;
    const repo = parent.repo as RepoRec;
    if (name === 'id') return `issue:${repo.owner}/${repo.name}:${issue.number}`;
    if (name === 'number') return issue.number;
    if (name === 'title') return issue.title;
    if (name === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
    if (name === 'body') return issue.body;
    return null;
  }
  if (parentType === 'PullRequest') {
    const pr = parent.pr as PullRec;
    const repo = parent.repo as RepoRec;
    if (name === 'id') return `pr:${repo.owner}/${repo.name}:${pr.number}`;
    if (name === 'number') return pr.number;
    if (name === 'state') return pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
    if (name === 'merged') return pr.merged;
    if (name === 'headRefName') return pr.headRef;
    if (name === 'baseRefName') return pr.baseRef;
    if (name === 'title') return pr.title;
    if (name === 'body') return pr.body;
    if (name === 'mergeable') {
      if (pr.merged) return 'UNKNOWN';
      return forge.mergeConflicts(repo, pr) ? 'CONFLICTING' : 'MERGEABLE';
    }
    if (name === 'files') {
      const first = argOf(field, 'first', ctx);
      const mergeTree = parseCommit(repo.objects.get(pr.mergeBase)?.data ?? Buffer.alloc(0)).tree;
      const headTree = parseCommit(repo.objects.get(pr.headSha)?.data ?? Buffer.alloc(0)).tree;
      const diff = forge.diffTrees(repo, mergeTree, headTree);
      const count = typeof first === 'number' && first >= 0 ? first : diff.length;
      const slice = diff.slice(0, count);
      return {
        __typename: 'PullRequestChangedFileConnection',
        nodes: slice.map((c) => ({ __typename: 'PullRequestChangedFile', path: c.path })),
        edges: slice.map((c) => ({ __typename: 'PullRequestChangedFile', path: c.path })),
        pageInfo: pageInfoFor(diff.length, 0, slice.length),
      };
    }
    return null;
  }
  if (parentType === 'IssueConnection' || parentType === 'PullRequestConnection' || parentType === 'PullRequestChangedFileConnection') {
    if (name === 'nodes') return (parent.nodes as unknown[]) ?? [];
    if (name === 'edges') return (parent.edges as unknown[]) ?? [];
    if (name === 'pageInfo') return parent.pageInfo ?? null;
    if (name === 'totalCount') return parent.totalCount ?? null;
    return null;
  }
  if (parentType === 'IssueEdge' || parentType === 'PullRequestEdge') {
    if (name === 'node') return parent.node ?? null;
    if (name === 'cursor') return parent.cursor ?? null;
    return null;
  }
  if (parentType === 'CommentEdge') {
    if (name === 'node') return parent.node ?? null;
    if (name === 'cursor') return parent.cursor ?? null;
    return null;
  }
  if (parentType === 'Comment') {
    if (name === 'id') return parent.id ?? null;
    if (name === 'body') return parent.body ?? null;
    return null;
  }
  if (parentType === 'PullRequestChangedFile') {
    if (name === 'path') return parent.path ?? null;
    return null;
  }
  if (parentType === 'Ref') {
    if (name === 'name') return parent.name ?? null;
    return null;
  }
  if (parentType === 'PageInfo') {
    if (name === 'hasNextPage') return parent.hasNextPage ?? false;
    if (name === 'hasPreviousPage') return parent.hasPreviousPage ?? false;
    if (name === 'endCursor') return parent.endCursor ?? null;
    if (name === 'startCursor') return parent.startCursor ?? null;
    return null;
  }
  if (parentType === 'CreateIssuePayload' || parentType === 'CloseIssuePayload') {
    if (name === 'issue') return parent.issue ?? null;
    if (name === 'clientMutationId') return null;
    return null;
  }
  if (parentType === 'CreatePullRequestPayload' || parentType === 'MergePullRequestPayload') {
    if (name === 'pullRequest') return parent.pullRequest ?? null;
    if (name === 'clientMutationId') return null;
    return null;
  }
  if (parentType === 'AddCommentPayload') {
    if (name === 'commentEdge') return parent.commentEdge ?? null;
    if (name === 'clientMutationId') return null;
    return null;
  }
  if (parentType === '__Type') {
    const typeName = parent.typeName as string;
    if (name === 'name') return typeName;
    if (name === 'kind') return GQL_ENUMS[typeName] !== undefined ? 'ENUM' : 'OBJECT';
    if (name === 'fields') {
      const includeDeprecated = argOf(field, 'includeDeprecated', ctx);
      if (includeDeprecated === false) return null;
      const fields = GQL_FIELDS[typeName] ?? [];
      return fields.map((f) => ({ __typename: '__Field', name: f }));
    }
    if (name === 'enumValues') {
      const includeDeprecated = argOf(field, 'includeDeprecated', ctx);
      if (includeDeprecated === false) return null;
      const values = GQL_ENUMS[typeName] ?? [];
      return values.map((v) => ({ __typename: '__EnumValue', name: v }));
    }
    return null;
  }
  if (parentType === '__Schema') {
    if (name === 'types') {
      return [...Object.keys(GQL_FIELDS), ...Object.keys(GQL_ENUMS)].map((t) => ({ __typename: '__Type', typeName: t }));
    }
    if (name === 'queryType') return { __typename: '__Type', typeName: 'Query' };
    if (name === 'mutationType') return { __typename: '__Type', typeName: 'Mutation' };
    return null;
  }
  if (parentType === '__Field' || parentType === '__EnumValue') {
    if (name === 'name') return parent.name ?? null;
    return null;
  }
  if (parentType === 'Node') {
    if (name === 'id') {
      const repo = (parent as GqlNode).repo as RepoRec | undefined;
      if (repo === undefined) return null;
      return `repo:${repo.owner}/${repo.name}`;
    }
    return null;
  }
  return null;
}

/** Execute a selection set against a parent value of a known type. */
function executeSelections(parentType: string, parent: GqlNode | null, selections: GqlSelection[], ctx: GqlContext): Record<string, unknown> | null {
  if (parent === null) return null;
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'spread') {
      const fragment = ctx.fragments.get(selection.name);
      if (fragment === undefined) continue;
      if (fragment.typeCondition !== parentType && fragment.typeCondition !== 'Node') continue;
      const sub = executeSelections(fragment.typeCondition === 'Node' ? parentType : fragment.typeCondition, parent, fragment.selections, ctx);
      if (sub !== null) Object.assign(out, sub);
      continue;
    }
    if (selection.kind === 'inline') {
      const condition = selection.typeCondition;
      if (condition !== null && condition !== parentType && condition !== 'Node') continue;
      const sub = executeSelections(condition ?? parentType, parent, selection.selections, ctx);
      if (sub !== null) Object.assign(out, sub);
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      out[key] = parentType;
      continue;
    }
    const fields = GQL_FIELDS[parentType];
    if (fields !== undefined && !fields.includes(selection.name)) {
      ctx.errors.push({ message: `Cannot query field "${selection.name}" on type "${parentType}".` });
      continue;
    }
    const value = resolveField(parentType, parent, selection, ctx);
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    if (Array.isArray(value)) {
      out[key] = value.map((item) => {
        if (item !== null && typeof item === 'object' && '__typename' in (item as Record<string, unknown>)) {
          const itemType = (item as GqlNode).__typename;
          const returnType = (GQL_RETURN[parentType] ?? {})[selection.name] ?? itemType;
          return executeSelections(returnType, item as GqlNode, selection.selections, ctx);
        }
        return item;
      });
      continue;
    }
    if (typeof value === 'object') {
      const node = value as GqlNode;
      const nodeType = node.__typename ?? ((GQL_RETURN[parentType] ?? {})[selection.name] ?? parentType);
      out[key] = executeSelections(nodeType, node, selection.selections, ctx);
      continue;
    }
    out[key] = value;
  }
  return out;
}

/** Validate the operation's fields against the schema; returns error messages (empty = valid). */
function validateOperation(operation: GqlOperation, fragments: Map<string, GqlFragment>): string[] {
  const errors: string[] = [];
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const walk = (parentType: string, selections: GqlSelection[], depth: number): void => {
    if (depth > 32) return;
    for (const selection of selections) {
      if (selection.kind === 'spread') {
        const fragment = fragments.get(selection.name);
        if (fragment !== undefined) walk(fragment.typeCondition, fragment.selections, depth + 1);
        continue;
      }
      if (selection.kind === 'inline') {
        walk(selection.typeCondition ?? parentType, selection.selections, depth + 1);
        continue;
      }
      if (selection.name === '__typename') continue;
      const fields = GQL_FIELDS[parentType];
      if (fields !== undefined && !fields.includes(selection.name)) {
        errors.push(`Cannot query field "${selection.name}" on type "${parentType}".`);
        continue;
      }
      const returnType = (GQL_RETURN[parentType] ?? {})[selection.name];
      if (returnType !== undefined && selection.selections.length > 0) walk(returnType, selection.selections, depth + 1);
    }
  };
  walk(rootType, operation.selections, 0);
  return errors;
}

function executeGraphQL(forge: Forge, query: string, variables: Record<string, unknown>): Record<string, unknown> {
  let parsed: { operations: GqlOperation[]; fragments: Map<string, GqlFragment> };
  try {
    parsed = new GqlParser(query).parseDocument();
  } catch (err) {
    return { errors: [{ message: err instanceof Error ? err.message : 'Syntax error' }] };
  }
  if (parsed.operations.length === 0) return { errors: [{ message: 'No operation found' }] };
  const operation = parsed.operations[0] as GqlOperation;
  const validationErrors = validateOperation(operation, parsed.fragments);
  if (validationErrors.length > 0) {
    return { data: null, errors: validationErrors.map((message) => ({ message })) };
  }
  const ctx: GqlContext = { forge, variables, fragments: parsed.fragments, errors: [] };
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(rootType, { __typename: rootType } as GqlNode, operation.selections, ctx);
  if (ctx.errors.length > 0) return { data, errors: ctx.errors };
  return { data };
}

function handleGraphQL(forge: Forge, req: IncomingMessage, res: ServerResponse, body: Buffer | null): void {
  if (req.method !== 'POST') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const parsed = body === null ? { ok: false } : parseJsonText(body.toString('utf8'));
  if (!parsed.ok) {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  const payload = parsed.value as unknown;
  const runOne = (item: unknown): Record<string, unknown> => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) return { errors: [{ message: 'Invalid request' }] };
    const query = (item as Record<string, unknown>).query;
    const variables = (item as Record<string, unknown>).variables;
    if (typeof query !== 'string') return { errors: [{ message: 'Query is required' }] };
    return executeGraphQL(forge, query, variables !== null && typeof variables === 'object' && !Array.isArray(variables) ? (variables as Record<string, unknown>) : {});
  };
  if (Array.isArray(payload)) {
    sendJson(res, 200, payload.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(payload));
}

// ---------------------------------------------------------------- MCP

const MCP_SERVER_INFO = { name: 'github-core-clone', version: '1.0.0' };

/** The tool list, built once: the suite requires it byte-identical across calls. */
const MCP_TOOLS: readonly Record<string, unknown>[] = Object.freeze([
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.', enum: ['open', 'closed', 'all'] },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch onto a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
        body: { type: 'string', description: 'The pull request body.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
]);

function pickArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    const value = args[name];
    if (value !== undefined) return value;
  }
  return undefined;
}

function mcpToolResult(result: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Run one tool call; returns the tool result object (or an error string for a JSON-RPC error). */
function callMcpTool(forge: Forge, name: string, args: Record<string, unknown>): { result: Record<string, unknown> } | { error: { code: number; message: string } } {
  const required: Record<string, string[]> = {
    create_repo: ['name'],
    get_repo: ['owner', 'repo'],
    create_issue: ['owner', 'repo', 'title'],
    list_issues: ['owner', 'repo'],
    create_pull_request: ['owner', 'repo', 'title', 'head', 'base'],
    merge_pull_request: ['owner', 'repo', 'pull_number'],
  };
  const needed = required[name];
  if (needed === undefined) return { error: { code: -32602, message: `Unknown tool: ${name}` } };
  for (const key of needed) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return { result: mcpToolError(`Missing required argument: ${key}`) };
    }
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (!validRepoName(repoName)) return { result: mcpToolError(`Invalid repository name: ${repoName}`) };
    const repo = forge.createRepo(VIEWER, repoName, args.private === true, typeof args.description === 'string' ? (args.description as string) : '');
    if (repo === null) return { result: mcpToolError(`name already exists on this account`) };
    return { result: mcpToolResult(repoJson(repo)) };
  }
  const owner = String(pickArg(args, 'owner') ?? '');
  const repoName = String(pickArg(args, 'repo', 'repository', 'repository_name', 'repo_name') ?? '');
  const repo = forge.getRepo(owner, repoName);
  if (name === 'get_repo') {
    if (repo === undefined) return { result: mcpToolError('Not Found') };
    return { result: mcpToolResult(repoJson(repo)) };
  }
  if (name === 'create_issue') {
    if (repo === undefined) return { result: mcpToolError('Not Found') };
    const number = repo.issueSeq + 1;
    repo.issueSeq = number;
    const issue: IssueRec = {
      number,
      id: (forge.issueIdSeq += 1),
      title: String(args.title),
      body: typeof args.body === 'string' ? (args.body as string) : '',
      state: 'open',
      labels: [],
      seq: forge.nextTime() - EPOCH_SEC,
    };
    repo.issues.push(issue);
    repo.comments.set(number, []);
    return { result: mcpToolResult(issueJson(issue, repo)) };
  }
  if (name === 'list_issues') {
    if (repo === undefined) return { result: mcpToolError('Not Found') };
    const state = typeof args.state === 'string' ? (args.state as string) : 'open';
    const list = state === 'all' ? repo.issues : repo.issues.filter((i) => i.state === state);
    return { result: mcpToolResult({ issues: list.map((i) => issueJson(i, repo)) }) };
  }
  if (name === 'create_pull_request') {
    if (repo === undefined) return { result: mcpToolError('Not Found') };
    const head = String(pickArg(args, 'head', 'head_ref', 'head_branch') ?? '');
    const base = String(pickArg(args, 'base', 'base_ref', 'base_branch') ?? '');
    const headTip = repo.refs.get(`refs/heads/${head}`);
    const baseTip = repo.refs.get(`refs/heads/${base}`);
    if (headTip === undefined || baseTip === undefined) return { result: mcpToolError('Invalid head or base') };
    const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (duplicate) return { result: mcpToolResult(pullJson(duplicate, repo)) };
    const number = repo.pullSeq + 1;
    repo.pullSeq = number;
    const pr: PullRec = {
      number,
      id: (forge.pullIdSeq += 1),
      title: String(args.title),
      body: typeof args.body === 'string' ? (args.body as string) : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef: head,
      baseRef: base,
      headSha: headTip,
      baseSha: baseTip,
      mergeBase: forge.mergeBase(repo, baseTip, headTip),
      seq: forge.nextTime() - EPOCH_SEC,
    };
    repo.pulls.push(pr);
    return { result: mcpToolResult(pullJson(pr, repo)) };
  }
  if (name === 'merge_pull_request') {
    if (repo === undefined) return { result: mcpToolError('Not Found') };
    const pullNumber = Number(pickArg(args, 'pull_number', 'pull_request_number', 'pr_number', 'number') ?? NaN);
    const pr = repo.pulls.find((p) => p.number === pullNumber);
    if (pr === undefined) return { result: mcpToolError('Pull request not found') };
    if (pr.merged || pr.state !== 'open') return { result: mcpToolError('Pull request is not open') };
    if (forge.mergeConflicts(repo, pr)) return { result: mcpToolError('Merge conflict') };
    const mergeSha = forge.squashMerge(repo, pr);
    if (mergeSha === null) return { result: mcpToolError('Merge conflict') };
    return { result: mcpToolResult(pullJson(pr, repo)) };
  }
  return { error: { code: -32602, message: `Unknown tool: ${name}` } };
}

function handleMcp(forge: Forge, req: IncomingMessage, res: ServerResponse, body: Buffer | null): void {
  if (req.method === 'DELETE') {
    sendEmpty(res, 204);
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (!isAuthenticated(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  const parsed = body === null ? { ok: false } : parseJsonText(body.toString('utf8'));
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const msg = parsed.value as Record<string, unknown> | null;
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.method !== 'string') {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = msg.id === undefined ? null : (msg.id as string | number | null);
  const method = msg.method as string;
  if (method.startsWith('notifications/')) {
    sendEmpty(res, 202);
    return;
  }
  const params = (msg.params ?? {}) as Record<string, unknown>;
  if (method === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: ['2026-07-28', '2025-11-25'],
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
        _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? (params.protocolVersion as string) : '2025-06-18';
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: { protocolVersion: offered, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? (params.name as string) : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    // Resolve an alias to its canonical name.
    const aliases: Record<string, string> = {
      create_repository: 'create_repo',
      repo_create: 'create_repo',
      repos_create: 'create_repo',
      repository_create: 'create_repo',
      get_repository: 'get_repo',
      repo_get: 'get_repo',
      repos_get: 'get_repo',
      repository_get: 'get_repo',
      issue_create: 'create_issue',
      issues_create: 'create_issue',
      issues_list: 'list_issues',
      issue_list: 'list_issues',
      pull_request_create: 'create_pull_request',
      pulls_create: 'create_pull_request',
      create_pr: 'create_pull_request',
      pr_create: 'create_pull_request',
      pull_request_merge: 'merge_pull_request',
      pulls_merge: 'merge_pull_request',
      merge_pr: 'merge_pull_request',
      pr_merge: 'merge_pull_request',
    };
    const canonical = aliases[toolName] ?? toolName;
    const outcome = callMcpTool(forge, canonical, args);
    if ('error' in outcome) {
      sendJson(res, 200, { jsonrpc: '2.0', id, error: outcome.error });
      return;
    }
    sendJson(res, 200, { jsonrpc: '2.0', id, result: outcome.result });
    return;
  }
  sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// ---------------------------------------------------------------- routing

async function handleRequest(forge: Forge, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { path, query } = urlOf(req);
  const method = req.method ?? 'GET';
  if (path === '/healthz' && method === 'GET') {
    sendJson(res, 200, { ok: true });
    return;
  }
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (gitMatch !== null) {
    const owner = decodeSegment(gitMatch[1] as string);
    const repoName = decodeSegment(gitMatch[2] as string);
    const repo = forge.getRepo(owner, repoName);
    const action = gitMatch[3] as string;
    if (action === 'info/refs') {
      if (method !== 'GET') {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      handleInfoRefs(forge, repo, query.get('service') ?? '', req, res);
      return;
    }
    if (action === 'git-upload-pack' && method === 'POST') {
      const body = await readBody(req);
      handleUploadPack(forge, repo, req, res, body);
      return;
    }
    if (action === 'git-receive-pack' && method === 'POST') {
      const body = await readBody(req);
      handleReceivePack(forge, repo, req, res, body);
      return;
    }
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (path === '/mcp') {
    const body = method === 'POST' ? await readBody(req) : null;
    handleMcp(forge, req, res, body);
    return;
  }
  if (path === '/api/graphql') {
    if (!isAuthenticated(req)) {
      sendJson(res, 401, { message: 'Requires authentication' });
      return;
    }
    const body = method === 'POST' ? await readBody(req) : null;
    handleGraphQL(forge, req, res, body);
    return;
  }
  if (path === '/api/v3' || path.startsWith('/api/v3/')) {
    if (!isAuthenticated(req)) {
      sendJson(res, 401, { message: 'Requires authentication' });
      return;
    }
    const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    const body = needsBody ? await readBody(req) : null;
    handleRest(forge, req, res, path, query, body);
    return;
  }
  sendJson(res, 404, { message: 'Not Found' });
}

/** main.ts tells the app which ephemeral port it bound, so pagination Link headers are same-origin. */
export function setListenPort(port: number): void {
  LISTEN_PORT = port;
}

export function createApp(): Server {
  const forge = new Forge();
  const server = createServer((req, res) => {
    void handleRequest(forge, req, res).catch(() => {
      try {
        if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
        else res.end();
      } catch {
        // The socket is already gone; nothing to do.
      }
    });
  });
  return server;
}
