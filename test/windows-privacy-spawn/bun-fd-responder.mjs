import fs from "node:fs";
import { dlopen, FFIType } from "bun:ffi";

const input = Buffer.alloc(4_096);
try {
  let bytesRead = 0;
  while (bytesRead < input.byteLength) {
    const count = fs.readSync(
      3,
      input,
      bytesRead,
      input.byteLength - bytesRead,
      null,
    );
    if (count === 0) break;
    bytesRead += count;
  }
  if (bytesRead < 1) throw new Error("missing probe request");
  const request = JSON.parse(input.subarray(0, bytesRead).toString("utf8"));
  if (
    typeof request.payload !== "string" ||
    !Number.isSafeInteger(request.canaryHandle) ||
    request.canaryHandle <= 0 ||
    typeof request.privacyToken !== "string" ||
    typeof request.transportPath !== "string"
  ) {
    throw new Error("invalid probe request");
  }

  const kernel32 = dlopen("kernel32.dll", {
    GetHandleInformation: {
      args: [FFIType.u64, FFIType.ptr],
      returns: FFIType.bool,
    },
    GetLastError: { args: [], returns: FFIType.u32 },
  });
  const handleFlags = new Uint32Array(1);
  const canaryValid = kernel32.symbols.GetHandleInformation(
    request.canaryHandle,
    handleFlags,
  );
  const canaryError = kernel32.symbols.GetLastError();
  kernel32.close();

  const handleText = String(request.canaryHandle);
  const argvAndEnvironmentClean =
    process.argv.every((value) => !value.includes(handleText)) &&
    Object.values(process.env).every((value) => value !== handleText) &&
    [request.privacyToken, request.transportPath].every(
      (secret) =>
        process.argv.every((value) => !value.includes(secret)) &&
        Object.values(process.env).every(
          (value) => value === undefined || !value.includes(secret),
        ),
    );
  const response = {
    payload: request.payload,
    canaryInvalid: !canaryValid && canaryError === 6,
    canaryError,
    stdioValid: [0, 1, 2].map((fd) => {
      try {
        fs.fstatSync(fd);
        return true;
      } catch {
        return false;
      }
    }),
    argvAndEnvironmentClean,
  };

  fs.writeSync(4, JSON.stringify(response));
  process.exitCode = 0;
} catch {
  process.exitCode = 1;
} finally {
  input.fill(0);
}
