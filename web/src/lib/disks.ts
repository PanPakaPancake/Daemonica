// Types and helpers of the disks page (M1.7b, DEC-032).
import type { Change } from "../components/ChangeFlow";

export interface Block {
  name: string;
  path: string;
  type: string;
  size: number;
  fstype?: string;
  fsver?: string;
  uuid?: string;
  partuuid?: string;
  label?: string;
  mountpoints: string[];
  model?: string;
  serial?: string;
  ro: boolean;
  rm: boolean;
  rota: boolean;
  tran?: string;
  fsused?: number;
  fsavail?: number;
  children?: Block[];
}

export interface MountInfo {
  device: string;
  mountpoint: string;
  fstype: string;
  total: number;
  used: number;
  available: number;
  used_pct: number;
  inodes_total: number;
  inodes_used: number;
  inodes_pct: number;
  read_only: boolean;
}

export interface Entry {
  spec: string;
  file: string;
  type: string;
  options: string;
  freq: number;
  pass: number;
  line: number;
}

export interface Fstab {
  entries: Entry[];
  text: string;
  errors?: string[];
}

export interface Swap {
  device: string;
  type: string;
  size: number;
  used: number;
}

export interface Overview {
  blocks: Block[];
  mounts: MountInfo[];
  fstab: Fstab;
  swaps: Swap[];
  error?: string;
}

export interface Problem {
  index: number;
  field?: string;
  code: string;
  msg?: string;
  warning?: boolean;
}

export interface FstabCheck {
  problems: Problem[];
  diff: string;
  change?: Change;
  entries: Entry[];
  blocking: boolean;
}

export interface MountResult {
  ok: boolean;
  users: { pid: number; comm: string; why: string }[];
  log: string[];
}

/** A block device with its depth in the tree. */
export interface Row extends Block {
  depth: number;
}

/** Flattens the device tree (depth first) for a table. */
export function flatten(bs: Block[], depth = 0): Row[] {
  return bs.flatMap((b) => [{ ...b, depth }, ...flatten(b.children ?? [], depth + 1)]);
}

/** Mount points that must not be unmounted (same rule as the helper). */
export function critical(mp: string): boolean {
  if (["/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/var/log", "/var/lib", "/home", "/tmp", "/etc", "/opt"].includes(mp)) return true;
  return ["/proc", "/sys", "/dev", "/run"].some((p) => mp === p || mp.startsWith(p + "/"));
}

/** Option templates offered in the fstab editor. */
export const optionTemplates = ["defaults", "nofail", "noexec,nosuid,nodev", "noatime", "ro", "x-systemd.device-timeout=10s"];

/** Adds the options of a template that are not set yet; "defaults" is dropped once others exist. */
export function addOptions(cur: string, tpl: string): string {
  const have = cur
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const o of tpl.split(",")) if (!have.includes(o)) have.push(o);
  const out = have.length > 1 ? have.filter((o) => o !== "defaults") : have;
  return out.join(",");
}

/** A new fstab entry for a device (UUID preferred; nofail for data disks). */
export function entryFor(b: Block, mountpoint: string): Entry {
  const swap = b.fstype === "swap";
  return {
    spec: b.uuid ? `UUID=${b.uuid}` : b.path,
    file: swap ? "none" : mountpoint,
    type: b.fstype || "auto",
    options: swap ? "sw" : "defaults,nofail",
    freq: 0,
    pass: swap ? 0 : 2,
    line: 0,
  };
}

/** Devices that can be put into fstab (a file system, not yet mounted). */
export function mountable(b: Block): boolean {
  return !!b.fstype && !["LVM2_member", "crypto_LUKS", "linux_raid_member", "zfs_member", "iso9660"].includes(b.fstype) && b.mountpoints.length === 0;
}

export const sameEntry = (a: Entry, b: Entry) =>
  a.spec === b.spec && a.file === b.file && a.type === b.type && a.options === b.options && a.freq === b.freq && a.pass === b.pass;
