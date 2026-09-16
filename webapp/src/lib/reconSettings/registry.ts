/**
 * The recon settings registry, on the TypeScript side.
 *
 * `registry.json` beside this file is a build artifact of
 * `recon_settings/registry.yaml`; it is the same bytes the recon pipeline
 * reads, and `recon_settings/build.py --check` fails the gate if either copy is
 * stale. Edit the YAML, never either JSON.
 *
 * This module is the query layer every derived list goes through. Nothing else
 * should reach into the JSON directly: a consumer that writes its own filter is
 * a second definition of a list the registry already answers, which is the
 * drift this whole directory removes.
 *
 * Prisma stays the source of truth for existence, type and `@default()`, so the
 * helpers below read those from the DMMF rather than from the registry. That
 * independence is what makes the alignment tests mean something: if they read
 * the registry's joined copy the comparison would be a tautology.
 */
import { Prisma } from '@prisma/client'

import registryJson from './registry.json'

export type McpDisposition = 'settable' | 'create_only' | 'tighten_only' | 'never'
export type Traffic = 'none' | 'passive' | 'active'
export type Phase =
  | 'domain_discovery'
  | 'port_scan'
  | 'http_probe'
  | 'resource_enum'
  | 'vuln_scan'
  | 'js_recon'
  | 'standalone'
export type Unit =
  | 'rps' | 'seconds' | 'minutes' | 'milliseconds' | 'threads' | 'count'
  | 'bytes' | 'depth' | 'percent' | 'ratio' | 'port' | 'none'
export type Validator =
  | 'docker_image' | 'http_header' | 'project_file' | 'status_codes' | 'severity'
  | 'scan_modules' | 'hostname' | 'url' | 'port_spec' | 'free_text' | 'identifier'
  | 'json_object'
export type TightenDirection =
  | 'decrease' | 'increase' | 'superset' | 'true_to_false' | 'false_to_true' | 'narrow'
export type DenyReason = 'identity' | 'internal' | 'escalation' | 'secret' | 'upload-managed'

/** The coarse shape a value is validated against, joined from Prisma. */
export type FieldType =
  | 'boolean' | 'int' | 'float' | 'string' | 'string-list' | 'number-list'
  | 'json' | 'datetime'

export interface RegistryField {
  tool: string
  runtime_key: string | null
  unit: Unit
  phase: Phase
  traffic: Traffic
  roe_capped: boolean
  mcp: McpDisposition
  meaning: string
  bounds?: { min: number; max: number }
  values?: string[]
  validator?: Validator
  zero_means?: 'unlimited' | 'disabled' | 'auto' | 'literal'
  fallback?: 'missing' | 'falsy'
  coerce?: 'int' | 'strip' | 'strip_list'
  tighten?: TightenDirection
  deny_reason?: DenyReason
  written_by?: string
  group?: string
  // joined from Prisma at build time
  type: FieldType
  prisma_type: string
  optional: boolean
  default: unknown
  has_default: boolean
}

export interface RegistryTool {
  title: string
  phase: Phase
  traffic: Traffic
  vendor?: string | null
  image?: string | null
  enabled_key?: string | null
  module?: string | null
  isolated_fn?: string | null
  graph_writer?: string | null
  partial_recon_module?: string | null
  form_section?: string | null
  produces?: string[]
  description?: string
  footguns?: string[]
}

export interface RuntimeOnlyKey {
  source: 'internal' | 'env' | 'user_account'
  tool?: string
  unit: Unit
  roe_capped: boolean
  zero_means?: 'unlimited' | 'disabled' | 'auto' | 'literal'
  secret?: boolean
  meaning: string
}

export interface Registry {
  version: number
  fields: Record<string, RegistryField>
  tools: Record<string, RegistryTool>
  runtime_only: Record<string, RuntimeOnlyKey>
}

const REGISTRY = registryJson as unknown as Registry

export function loadRegistry(): Registry {
  return REGISTRY
}

/** Every Project scalar column Prisma knows about. */
export function prismaColumns(): string[] {
  return Object.keys(Prisma.ProjectScalarFieldEnum)
}

/**
 * column -> its `@default()` value, read from the DMMF.
 *
 * A function default (`cuid()`, `now()`, `autoincrement()`) has no value, so it
 * maps to `undefined`: the column exists and has a default, but not one this
 * layer can compare against a bound.
 */
export function prismaDefaults(): Record<string, unknown> {
  const model = Prisma.dmmf.datamodel.models.find(m => m.name === 'Project')
  if (!model) throw new Error('Prisma DMMF has no Project model')
  const out: Record<string, unknown> = {}
  for (const f of model.fields) {
    if (f.kind !== 'scalar' || !f.hasDefaultValue) continue
    const d = f.default
    if (d !== null && typeof d === 'object' && 'name' in d) continue // cuid(), now(), ...
    out[f.name] = d
  }
  return out
}

/** column -> its Prisma scalar type, list-ness included, read from the DMMF. */
export function prismaTypes(): Record<string, { type: string; isList: boolean }> {
  const model = Prisma.dmmf.datamodel.models.find(m => m.name === 'Project')
  if (!model) throw new Error('Prisma DMMF has no Project model')
  const out: Record<string, { type: string; isList: boolean }> = {}
  for (const f of model.fields) {
    if (f.kind !== 'scalar') continue
    out[f.name] = { type: f.type, isList: f.isList }
  }
  return out
}

export interface NamedField extends RegistryField {
  key: string
}

/** The query helper every derived list goes through. */
export function fieldsWhere(pred: (f: RegistryField, key: string) => boolean): NamedField[] {
  const out: NamedField[] = []
  for (const key of Object.keys(REGISTRY.fields).sort()) {
    const f = REGISTRY.fields[key]
    if (pred(f, key)) out.push({ key, ...f })
  }
  return out
}

export function field(key: string): RegistryField | undefined {
  return Object.prototype.hasOwnProperty.call(REGISTRY.fields, key)
    ? REGISTRY.fields[key]
    : undefined
}

export function fieldKeys(): string[] {
  return Object.keys(REGISTRY.fields).sort()
}

export function toolIds(): string[] {
  return Object.keys(REGISTRY.tools).sort()
}

export function tool(id: string): RegistryTool | undefined {
  return Object.prototype.hasOwnProperty.call(REGISTRY.tools, id)
    ? REGISTRY.tools[id]
    : undefined
}

// --- the derived lists ------------------------------------------------------------
// Each of these replaced a hand-maintained copy. They live here so there is one
// query per list rather than one per consumer.

/** Fields a token may write through `update_recon_settings`. */
export function settableFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'settable')
}

/** Fields `create_project` may set and nothing may change afterwards. */
export function createOnlyFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'create_only')
}

/** The RoE block: writable at creation, one direction only after. */
export function tightenOnlyFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'tighten_only')
}

/** Columns that are not pipeline parameters at all. */
export function neverFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'never')
}

/**
 * Every runtime key the engagement rate ceiling applies to, columns and
 * runtime-only keys together.
 *
 * This is the list `RATE_LIMIT_KEYS` used to hardcode. Being IN it is not the
 * same as being capped, which is why the runtime test asserts the resolved
 * value rather than membership.
 */
export function roeCappedRuntimeKeys(): string[] {
  const fromFields = fieldsWhere(f => f.roe_capped)
    .map(f => f.runtime_key)
    .filter((k): k is string => Boolean(k))
  const fromRuntime = Object.entries(REGISTRY.runtime_only)
    .filter(([, r]) => r.roe_capped)
    .map(([k]) => k)
  return [...new Set([...fromFields, ...fromRuntime])].sort()
}

/** Concurrency knobs the memory governor scales by ratio. */
export function governorRatioKeys(): string[] {
  return fieldsWhere(f => f.unit === 'threads' && f.runtime_key !== null)
    .map(f => f.runtime_key as string)
    .sort()
}

/** In-memory accumulators the memory governor budgets in bytes. */
export function governorBudgetKeys(): string[] {
  return fieldsWhere(f => (f.unit === 'count' || f.unit === 'bytes') && f.runtime_key !== null)
    .map(f => f.runtime_key as string)
    .sort()
}

/**
 * Fields whose change between enqueue and dispatch must re-confirm a queued job.
 *
 * Anything that steers WHERE or HOW HARD a job scans: every field that sends
 * traffic, the whole RoE block, and the scope columns. Once most of the model is
 * mutable, a narrower list means a scope-compliant configuration can become a
 * non-compliant run with nothing failing.
 */
export function fingerprintFields(): string[] {
  return fieldsWhere(
    f => f.traffic !== 'none' || f.mcp === 'tighten_only' || f.mcp === 'create_only'
  ).map(f => f.key)
}
