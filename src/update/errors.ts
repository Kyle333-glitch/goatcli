export type UpdateErrorCode =
  | "GOAT_UPDATE_DISABLED"
  | "GOAT_UPDATE_INVALID_ARGUMENT"
  | "GOAT_UPDATE_BUSY"
  | "GOAT_UPDATE_LOCK_INVALID"
  | "GOAT_UPDATE_MANIFEST_TOO_LARGE"
  | "GOAT_UPDATE_MANIFEST_INVALID"
  | "GOAT_UPDATE_MANIFEST_UNSUPPORTED"
  | "GOAT_UPDATE_SIGNATURE_INVALID"
  | "GOAT_UPDATE_SIGNING_KEY_UNKNOWN"
  | "GOAT_UPDATE_SIGNING_KEY_REVOKED"
  | "GOAT_UPDATE_METADATA_EXPIRED"
  | "GOAT_UPDATE_METADATA_REPLAYED"
  | "GOAT_UPDATE_METADATA_MISMATCH"
  | "GOAT_UPDATE_TARGET_NOT_FOUND"
  | "GOAT_UPDATE_TARGET_AMBIGUOUS"
  | "GOAT_UPDATE_TARGET_INCOMPATIBLE"
  | "GOAT_UPDATE_DOWNGRADE_BLOCKED"
  | "GOAT_UPDATE_REDIRECT_REJECTED"
  | "GOAT_UPDATE_NETWORK_POLICY"
  | "GOAT_UPDATE_NETWORK_TIMEOUT"
  | "GOAT_UPDATE_NETWORK_FAILED"
  | "GOAT_UPDATE_DOWNLOAD_TOO_LARGE"
  | "GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH"
  | "GOAT_UPDATE_ARTIFACT_HASH_MISMATCH"
  | "GOAT_UPDATE_TEMPORARY_FILE_UNSAFE"
  | "GOAT_UPDATE_ARCHIVE_INVALID"
  | "GOAT_UPDATE_ARCHIVE_LIMIT"
  | "GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH"
  | "GOAT_UPDATE_ARCHIVE_PATH_UNSAFE"
  | "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE"
  | "GOAT_UPDATE_COMPATIBILITY_FAILED"
  | "GOAT_UPDATE_CODE_SIGNATURE_INVALID"
  | "GOAT_UPDATE_HEALTH_CHECK_FAILED"
  | "GOAT_UPDATE_ROLLBACK_INVALID"
  | "GOAT_UPDATE_STATE_INVALID"
  | "GOAT_UPDATE_RECOVERY_REQUIRED"
  | "GOAT_UPDATE_ACTIVATION_FAILED";

const SAFE_MESSAGES: Readonly<Record<UpdateErrorCode, string>> = {
  GOAT_UPDATE_DISABLED:
    "Verified updates are unavailable because this launcher has no approved production update policy.",
  GOAT_UPDATE_INVALID_ARGUMENT:
    "The update command accepts only an optional stable, beta, or development channel.",
  GOAT_UPDATE_BUSY: "Another GOAT update is already in progress.",
  GOAT_UPDATE_LOCK_INVALID: "The updater lock could not be validated safely.",
  GOAT_UPDATE_MANIFEST_TOO_LARGE:
    "Update metadata exceeded its permitted size.",
  GOAT_UPDATE_MANIFEST_INVALID: "Update metadata is malformed or ambiguous.",
  GOAT_UPDATE_MANIFEST_UNSUPPORTED:
    "Update metadata uses an unsupported schema or TUF profile.",
  GOAT_UPDATE_SIGNATURE_INVALID:
    "Update metadata failed signature verification.",
  GOAT_UPDATE_SIGNING_KEY_UNKNOWN:
    "Update metadata contains an unauthorized signing key.",
  GOAT_UPDATE_SIGNING_KEY_REVOKED:
    "Update metadata contains a revoked signing key.",
  GOAT_UPDATE_METADATA_EXPIRED: "Update metadata has expired.",
  GOAT_UPDATE_METADATA_REPLAYED:
    "Update metadata is older than previously trusted metadata.",
  GOAT_UPDATE_METADATA_MISMATCH:
    "Update metadata files do not describe one consistent release.",
  GOAT_UPDATE_TARGET_NOT_FOUND:
    "No authenticated update matches this channel and computer.",
  GOAT_UPDATE_TARGET_AMBIGUOUS:
    "Authenticated metadata contains ambiguous matching updates.",
  GOAT_UPDATE_TARGET_INCOMPATIBLE:
    "The authenticated update is not compatible with this launcher.",
  GOAT_UPDATE_DOWNGRADE_BLOCKED:
    "The requested update would lower the trusted release sequence.",
  GOAT_UPDATE_REDIRECT_REJECTED: "The update server returned a redirect.",
  GOAT_UPDATE_NETWORK_POLICY:
    "The update request violates the approved network policy.",
  GOAT_UPDATE_NETWORK_TIMEOUT: "The update request timed out.",
  GOAT_UPDATE_NETWORK_FAILED: "The update resource could not be downloaded.",
  GOAT_UPDATE_DOWNLOAD_TOO_LARGE:
    "The update download exceeded its authenticated size limit.",
  GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH:
    "The downloaded artifact length does not match signed metadata.",
  GOAT_UPDATE_ARTIFACT_HASH_MISMATCH:
    "The downloaded artifact checksum does not match signed metadata.",
  GOAT_UPDATE_TEMPORARY_FILE_UNSAFE:
    "The updater could not create a private temporary file safely.",
  GOAT_UPDATE_ARCHIVE_INVALID: "The update archive is malformed.",
  GOAT_UPDATE_ARCHIVE_LIMIT:
    "The update archive exceeds a safe extraction limit.",
  GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH:
    "The update archive does not match its signed file list.",
  GOAT_UPDATE_ARCHIVE_PATH_UNSAFE:
    "The update archive contains an unsafe path.",
  GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE:
    "The update archive contains an unsafe entry type.",
  GOAT_UPDATE_COMPATIBILITY_FAILED:
    "The verified engine is incompatible with this launcher.",
  GOAT_UPDATE_CODE_SIGNATURE_INVALID:
    "The engine failed platform code-signing verification.",
  GOAT_UPDATE_HEALTH_CHECK_FAILED:
    "The verified engine did not pass its bounded health check.",
  GOAT_UPDATE_ROLLBACK_INVALID:
    "The existing rollback installation is missing or corrupted.",
  GOAT_UPDATE_STATE_INVALID:
    "The updater security state is missing, corrupt, or inconsistent.",
  GOAT_UPDATE_RECOVERY_REQUIRED:
    "The updater cannot choose a complete authenticated installation safely.",
  GOAT_UPDATE_ACTIVATION_FAILED:
    "The verified engine could not be activated safely.",
};

export class UpdateError extends Error {
  constructor(
    readonly code: UpdateErrorCode,
    options: { cause?: unknown } = {},
  ) {
    super(SAFE_MESSAGES[code], options);
    this.name = "UpdateError";
  }
}

export function formatUpdateError(error: UpdateError): string {
  return `GOAT update error [${error.code}]: ${SAFE_MESSAGES[error.code]}`;
}

export function asUpdateError(
  error: unknown,
  fallback: UpdateErrorCode,
): UpdateError {
  return error instanceof UpdateError
    ? error
    : new UpdateError(fallback, { cause: error });
}
