import {
  spawn,
  type ChildProcess,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { createInterface } from "node:readline";

const JOB_GUARD_START_TIMEOUT_MS = 15_000;
const JOB_GUARD_STOP_TIMEOUT_MS = 5_000;

const WINDOWS_JOB_GUARD_SCRIPT = `
$ErrorActionPreference = "Stop"
$source = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public sealed class GoatJobGuard : IDisposable
{
    private const uint PROCESS_TERMINATE = 0x0001;
    private const uint PROCESS_SET_QUOTA = 0x0100;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        int informationClass,
        IntPtr information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private IntPtr job;
    private IntPtr launcher;

    private GoatJobGuard(IntPtr jobHandle, IntPtr launcherHandle)
    {
        job = jobHandle;
        launcher = launcherHandle;
    }

    public static GoatJobGuard Create(int launcherProcessId)
    {
        IntPtr launcherHandle = OpenProcess(
            PROCESS_TERMINATE | PROCESS_SET_QUOTA |
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            false,
            launcherProcessId);
        if (launcherHandle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        IntPtr jobHandle = CreateJobObject(IntPtr.Zero, null);
        if (jobHandle == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(launcherHandle);
            throw new Win32Exception(error);
        }

        try
        {
            SetKillOnClose(jobHandle, true);
            return new GoatJobGuard(jobHandle, launcherHandle);
        }
        catch
        {
            CloseHandle(jobHandle);
            CloseHandle(launcherHandle);
            throw;
        }
    }

    public void Assign()
    {
        if (!AssignProcessToJobObject(job, launcher))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public uint ActiveProcesses()
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION value =
            new JOBOBJECT_BASIC_ACCOUNTING_INFORMATION();
        int length = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(value, buffer, false);
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                buffer,
                (uint)length,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            value = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(
                buffer,
                typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            return value.ActiveProcesses;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public bool LauncherExited()
    {
        uint result = WaitForSingleObject(launcher, 0);
        if (result == WAIT_OBJECT_0)
        {
            return true;
        }
        if (result == WAIT_TIMEOUT)
        {
            return false;
        }
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Disarm()
    {
        SetKillOnClose(job, false);
    }

    private static void SetKillOnClose(IntPtr jobHandle, bool enabled)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION value =
            new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        value.BasicLimitInformation.LimitFlags =
            enabled ? JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE : 0;
        int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(value, buffer, false);
            if (!SetInformationJobObject(
                jobHandle,
                JobObjectExtendedLimitInformation,
                buffer,
                (uint)length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        IntPtr launcherHandle = launcher;
        IntPtr jobHandle = job;
        launcher = IntPtr.Zero;
        job = IntPtr.Zero;
        if (launcherHandle != IntPtr.Zero)
        {
            CloseHandle(launcherHandle);
        }
        if (jobHandle != IntPtr.Zero)
        {
            CloseHandle(jobHandle);
        }
    }
}
"@

Add-Type -TypeDefinition $source -Language CSharp

$init = [Console]::In.ReadLine()
if ($null -eq $init) {
    throw "missing initialization"
}
$parts = $init.Split([char]" ")
$launcherProcessId = 0
if (
    $parts.Length -ne 3 -or
    $parts[0] -ne "INIT" -or
    -not [int]::TryParse($parts[1], [ref]$launcherProcessId) -or
    $launcherProcessId -le 0 -or
    $parts[2] -notmatch "^[A-Za-z0-9_-]{43}$"
) {
    throw "invalid initialization"
}
$nonce = $parts[2]
$guard = [GoatJobGuard]::Create($launcherProcessId)
try {
    [Console]::Out.WriteLine("OPEN " + $nonce)
    [Console]::Out.Flush()

    $commit = [Console]::In.ReadLine()
    if ($commit -ne ("COMMIT " + $nonce)) {
        throw "invalid commit"
    }

    $guard.Assign()
    [Console]::Out.WriteLine("READY " + $nonce)
    [Console]::Out.Flush()

    while ($true) {
        $readTask = [Console]::In.ReadLineAsync()
        while (-not $readTask.Wait(250)) {
            if ($guard.LauncherExited()) {
                return
            }
        }

        $command = $readTask.Result
        if ($null -eq $command) {
            return
        }
        if ($command -eq ("RELEASE " + $nonce)) {
            $active = $guard.ActiveProcesses()
            if ($active -eq 1 -and -not $guard.LauncherExited()) {
                $guard.Disarm()
            }
            return
        }
        if ($command -eq ("KILL " + $nonce)) {
            return
        }

        throw "invalid command"
    }
}
finally {
    $guard.Dispose()
}
`;

export interface WindowsJobContainment {
  release(): Promise<void>;
  terminate(): void;
}

export async function createWindowsJobContainment(options: {
  readonly launcherPid: number;
  readonly environment: NodeJS.ProcessEnv;
  readonly startTimeoutMs?: number;
  readonly stopTimeoutMs?: number;
}): Promise<WindowsJobContainment> {
  if (!Number.isSafeInteger(options.launcherPid) || options.launcherPid <= 0) {
    throw new Error("Windows process containment is unavailable.");
  }

  const powershellPath = resolveWindowsPowerShell(options.environment);
  const nonce = randomBytes(32).toString("base64url");
  const encodedCommand = Buffer.from(
    WINDOWS_JOB_GUARD_SCRIPT,
    "utf16le",
  ).toString("base64");
  const guard = spawn(
    powershellPath,
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      encodedCommand,
    ],
    {
      env: windowsGuardEnvironment(options.environment),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  guard.stderr.resume();
  guard.stdout.setEncoding("utf8");
  const lines = createInterface({
    input: guard.stdout,
    crlfDelay: Number.POSITIVE_INFINITY,
  });
  const iterator = lines[Symbol.asyncIterator]();
  const startTimeoutMs = options.startTimeoutMs ?? JOB_GUARD_START_TIMEOUT_MS;

  try {
    await writeGuardCommand(
      guard,
      "INIT " + String(options.launcherPid) + " " + nonce,
    );
    await expectGuardLine(guard, iterator, "OPEN " + nonce, startTimeoutMs);
    await writeGuardCommand(guard, "COMMIT " + nonce);
    await expectGuardLine(guard, iterator, "READY " + nonce, startTimeoutMs);
  } catch {
    lines.close();
    guard.stdin.destroy();
    terminateGuard(guard);
    throw new Error("Windows process containment is unavailable.");
  }

  let releasePromise: Promise<void> | undefined;
  let terminationPromise: Promise<void> | undefined;
  let terminating = false;
  return {
    release() {
      if (releasePromise) return releasePromise;
      if (terminationPromise) return terminationPromise;
      releasePromise = (async () => {
        lines.close();
        if (guard.exitCode !== null || guard.signalCode !== null) {
          throw new Error("Windows process containment ended unexpectedly.");
        }
        await writeGuardCommand(guard, "RELEASE " + nonce, true);
        try {
          await waitForGuardExit(
            guard,
            options.stopTimeoutMs ?? JOB_GUARD_STOP_TIMEOUT_MS,
          );
        } catch {
          terminateGuard(guard);
          throw new Error("Windows process containment did not stop safely.");
        }
        if (guard.exitCode !== 0) {
          throw new Error("Windows process containment ended unexpectedly.");
        }
      })();
      return releasePromise;
    },
    terminate() {
      if (terminating || releasePromise) return;
      terminating = true;
      terminationPromise = (async () => {
        lines.close();
        try {
          await writeGuardCommand(guard, "KILL " + nonce, true);
          await waitForGuardExit(
            guard,
            options.stopTimeoutMs ?? JOB_GUARD_STOP_TIMEOUT_MS,
          );
        } catch {
          terminateGuard(guard);
          try {
            await waitForGuardExit(
              guard,
              options.stopTimeoutMs ?? JOB_GUARD_STOP_TIMEOUT_MS,
            );
          } catch {
            throw new Error("Windows process containment did not stop safely.");
          }
        }
      })().catch(() => undefined);
    },
  };
}

function resolveWindowsPowerShell(environment: NodeJS.ProcessEnv): string {
  const systemRoot =
    environment.SystemRoot ??
    environment.SYSTEMROOT ??
    environment.WINDIR ??
    environment.windir;
  if (
    !systemRoot ||
    systemRoot.includes("\0") ||
    !path.win32.isAbsolute(systemRoot)
  ) {
    throw new Error("Windows process containment is unavailable.");
  }
  return path.win32.join(
    systemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
}

function windowsGuardEnvironment(
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  for (const key of ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) {
    const value = environment[key];
    if (value !== undefined) result[key] = value;
  }
  return result;
}

async function writeGuardCommand(
  guard: ChildProcessWithoutNullStreams,
  command: string,
  end = false,
): Promise<void> {
  if (!/^[A-Z]+ [A-Za-z0-9_-]+(?: [A-Za-z0-9_-]+)?$/.test(command)) {
    throw new Error("Invalid process-containment command.");
  }
  await new Promise<void>((resolve, reject) => {
    const callback = (error?: Error | null): void => {
      if (error) reject(error);
      else resolve();
    };
    if (end) {
      guard.stdin.end(command + "\n", callback);
    } else {
      guard.stdin.write(command + "\n", callback);
    }
  });
}

async function expectGuardLine(
  guard: ChildProcess,
  iterator: AsyncIterator<string>,
  expected: string,
  timeoutMs: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      guard.removeListener("error", onFailure);
      guard.removeListener("exit", onFailure);
      if (error) reject(error);
      else resolve();
    };
    const onFailure = (): void =>
      finish(new Error("Process-containment guard failed."));
    const timer = setTimeout(
      () => finish(new Error("Process-containment guard timed out.")),
      timeoutMs,
    );
    guard.once("error", onFailure);
    guard.once("exit", onFailure);
    void iterator.next().then(
      (result) => {
        if (result.done || result.value !== expected) {
          finish(new Error("Process-containment guard protocol failed."));
          return;
        }
        finish();
      },
      () => finish(new Error("Process-containment guard protocol failed.")),
    );
  });
}

async function waitForGuardExit(
  guard: ChildProcess,
  timeoutMs: number,
): Promise<void> {
  if (guard.exitCode !== null || guard.signalCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      guard.removeListener("error", onError);
      guard.removeListener("exit", onExit);
      if (error) reject(error);
      else resolve();
    };
    const onError = (): void =>
      finish(new Error("Process-containment guard failed."));
    const onExit = (): void => finish();
    const timer = setTimeout(
      () => finish(new Error("Process-containment guard timed out.")),
      timeoutMs,
    );
    guard.once("error", onError);
    guard.once("exit", onExit);
  });
}

function terminateGuard(guard: ChildProcess): void {
  try {
    guard.kill();
  } catch {
    // The guard may already be gone.
  }
}
