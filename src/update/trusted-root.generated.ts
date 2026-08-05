/**
 * Production TUF trust material for GOAT v0.4.0.
 *
 * The approved design requires real public root metadata to be generated from
 * the release-policy repository. That input is not present in this workspace,
 * so production updates remain fail-closed. Tests inject clearly labeled
 * ephemeral roots and never use this module as a trust root.
 */
export const GOAT_TUF_ROOT_BASE64: string | null = null;
export const GOAT_TUF_ROOT_SHA256: string | null = null;
