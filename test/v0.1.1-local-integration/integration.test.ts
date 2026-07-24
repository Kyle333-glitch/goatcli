import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  launchEngine,
  launchValidatedEngine,
  type ProcessLike,
  type SpawnEngine,
} from "../../src/engine/launch.js";
import type {
  GoatArchitecture,
  GoatPlatform,
  ResolvedEngine,
} from "../../src/engine/contract.js";

const TEST_TIMEOUT_MS = 8_000;

function currentPlatform(): GoatPlatform {
  assert.ok(
    process.platform === "win32" || process.platform === "darwin",
    "launcher integration tests require Windows or macOS",
  );
  return process.platform;
}

function currentArchitecture(): GoatArchitecture {
  assert.ok(
    process.arch === "x64" || process.arch === "arm64",
    "launcher integration tests require x64 or arm64",
  );
  return process.arch;
}

function developmentEngine(): ResolvedEngine {
  return {
    executablePath: process.execPath,
    manifestPath: null,
    source: "development",
    releaseChannel: "dev",
    platform: currentPlatform(),
    architecture: currentArchitecture(),
    developmentOverride: true,
  };
}

async function launchNode(
  args: readonly string[],
  options: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    processLike?: ProcessLike;
    spawnEngine?: SpawnEngine;
  } = {},
) {
  return withTimeout(
    launchEngine({
      launcherVersion: "0.0.6",
      args,
      cwd: options.cwd,
      env: options.env,
      processLike: options.processLike,
      spawnEngine: options.spawnEngine,
      processTerminator: () => ({ status: 0 }),
      resolvedEngine: developmentEngine(),
      nodeVersion: "24.16.0",
    }),
  );
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs = TEST_TIMEOUT_MS,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error("bounded launcher integration timed out")),
          timeoutMs,
        );
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function waitForFile(filePath: string): Promise<void> {
  const deadline = Date.now() + TEST_TIMEOUT_MS;
  while (!fs.existsSync(filePath)) {
    if (Date.now() >= deadline) {
      throw new Error("bounded launcher readiness wait timed out");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function makeProcessLike(
  emitter: EventEmitter,
  cwd: string,
  env: NodeJS.ProcessEnv = process.env,
): ProcessLike {
  return {
    platform: currentPlatform(),
    arch: currentArchitecture(),
    pid: process.pid,
    env,
    cwd: () => cwd,
    on: emitter.on.bind(emitter) as ProcessLike["on"],
    removeListener: emitter.removeListener.bind(
      emitter,
    ) as ProcessLike["removeListener"],
  };
}

test("launcher starts engine and forwards non-launcher args unchanged", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "goat-test-"));
  try {
    const outputPath = path.join(tmpDir, "SOURCE_CODE_SECRET_4JK2.json");
    const forwarded = [
      "run",
      "--flag",
      "value with spaces",
      "PROMPT_SECRET_7QX9",
    ];
    const script =
      'require("node:fs").writeFileSync(process.argv[1], JSON.stringify(process.argv.slice(2)))';

    const result = await launchNode(["-e", script, outputPath, ...forwarded]);

    assert.equal(result.exitCode, 0);
    assert.deepEqual(
      JSON.parse(fs.readFileSync(outputPath, "utf8")),
      forwarded,
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("engine receives the exact working directory without launcher inspection", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "goat-test-"));
  try {
    const workDir = path.join(tmpDir, "work dir PATH_SECRET_3HT6");
    const outputPath = path.join(tmpDir, "TOKEN_SECRET_8MVP-cwd.txt");
    fs.mkdirSync(workDir, { recursive: true });
    const script =
      'require("node:fs").writeFileSync(process.argv[1], process.cwd())';

    const result = await launchNode(["-e", script, outputPath], {
      cwd: workDir,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(fs.readFileSync(outputPath, "utf8"), workDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("engine receives only minimal environment values", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "goat-test-"));
  try {
    const outputPath = path.join(tmpDir, "environment.json");
    const script =
      'const fs=require("node:fs");fs.writeFileSync(process.argv[1],JSON.stringify({path:process.env.PATH,provider:process.env.ENV_SECRET_9DK1,controlPlane:process.env.GOAT_CONTROL_PLANE_URL,enginePath:process.env.GOAT_ENGINE_PATH}))';
    const env = {
      ...process.env,
      PATH: process.env.PATH ?? "",
      ENV_SECRET_9DK1: "TOKEN_SECRET_8MVP",
      GOAT_CONTROL_PLANE_URL: "https://example.invalid/SOURCE_CODE_SECRET_4JK2",
      GOAT_ENGINE_PATH: path.join(tmpDir, "PATH_SECRET_3HT6"),
    };

    const result = await launchNode(["-e", script, outputPath], { env });
    const childEnvironment = JSON.parse(fs.readFileSync(outputPath, "utf8"));

    assert.equal(result.exitCode, 0);
    assert.deepEqual(childEnvironment, { path: env.PATH });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("child output remains inherited and absent from launcher-owned results", async () => {
  let captured = "";
  let captureComplete = Promise.resolve();
  const spawnEngine: SpawnEngine = (command, args, options) => {
    assert.deepEqual(options.stdio, [
      "inherit",
      "inherit",
      "inherit",
      "pipe",
      "pipe",
    ]);
    const child = spawn(command, [...args], {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout?.on("data", (chunk) => {
      captured += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      captured += String(chunk);
    });
    captureComplete = new Promise((resolve) => child.once("close", resolve));
    return child;
  };

  const result = await launchNode(
    [
      "-e",
      'console.log("SOURCE_CODE_SECRET_4JK2");console.error("TOKEN_SECRET_8MVP")',
    ],
    { spawnEngine },
  );
  await captureComplete;

  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.deepEqual(Object.keys(result).sort(), ["exitCode", "signal"]);
  assert.equal(captured.includes("SOURCE_CODE_SECRET_4JK2"), true);
  assert.equal(captured.includes("TOKEN_SECRET_8MVP"), true);
});

test("native Node child completes authenticated fd 3/4 privacy handshake", async () => {
  const script = [
    'const fs=require("node:fs");',
    'const crypto=require("node:crypto");',
    "const readExact=(fd,count)=>{const bytes=Buffer.alloc(count);let offset=0;while(offset<count){const read=fs.readSync(fd,bytes,offset,count-offset,null);if(read<1)throw new Error('closed');offset+=read;}return bytes;};",
    "const bootstrap=readExact(3,40);",
    "if(bootstrap.subarray(0,8).toString('utf8')!=='GOATIPC1')process.exit(2);",
    "const secret=bootstrap.subarray(8);",
    "const prefix=readExact(3,6);",
    "const headerLength=prefix.readUInt32BE(0);",
    "const credentialLength=prefix.readUInt16BE(4);",
    "const body=readExact(3,headerLength+credentialLength+32);",
    "const authenticated=Buffer.concat([prefix,body.subarray(0,headerLength+credentialLength)]);",
    "const expected=crypto.createHmac('sha256',secret).update(Buffer.from('GOAT launcher IPC request v1\\0')).update(authenticated).digest();",
    "if(!crypto.timingSafeEqual(expected,body.subarray(headerLength+credentialLength)))process.exit(3);",
    "const request=JSON.parse(body.subarray(0,headerLength).toString('utf8'));",
    "const responseHeader=Buffer.from(JSON.stringify({protocol_version:1,message_type:'session_ack',session_id:request.session_id,sequence:request.sequence,status:'accepted'}));",
    "const responsePrefix=Buffer.alloc(6);responsePrefix.writeUInt32BE(responseHeader.length,0);",
    "const responseAuthenticated=Buffer.concat([responsePrefix,responseHeader]);",
    "const responseTag=crypto.createHmac('sha256',secret).update(Buffer.from('GOAT launcher IPC response v1\\0')).update(responseAuthenticated).digest();",
    "fs.writeSync(4,Buffer.concat([responseAuthenticated,responseTag]));",
    "bootstrap.fill(0);secret.fill(0);body.fill(0);expected.fill(0);responseTag.fill(0);",
  ].join("");

  const result = await withTimeout(
    launchValidatedEngine(
      { executablePath: process.execPath, platform: currentPlatform() },
      ["-e", script],
      {
        cwd: process.cwd(),
        environment: { ...process.env },
        privacyIpc: {
          mode: "eager",
          engineIntegrity: "development_unverified",
          credentialStore: "not_checked",
          launcherPid: process.pid,
        },
      },
    ),
  );

  assert.deepEqual(result, { exitCode: 0, signal: null });
});

test("exit code propagates from engine to launcher", async () => {
  const result = await launchNode(["-e", "process.exit(42)"]);
  assert.equal(result.exitCode, 42);
});

test("cancellation interrupts an active engine and leaves no child", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "goat-test-"));
  let child: ChildProcess | undefined;
  try {
    const readyPath = path.join(tmpDir, "ready");
    const emitter = new EventEmitter();
    const processLike = makeProcessLike(emitter, process.cwd());
    const spawnEngine: SpawnEngine = (command, args, options) => {
      child = spawn(command, [...args], options);
      return child;
    };
    const script =
      'require("node:fs").writeFileSync(process.argv[1], "ready");setInterval(() => {}, 1000)';

    const launchPromise = launchNode(["-e", script, readyPath], {
      processLike,
      spawnEngine,
    });
    await waitForFile(readyPath);
    emitter.emit("SIGTERM");

    const result = await launchPromise;
    assert.notEqual(result.exitCode, 0);
    assert.ok(child);
    assert.ok(child.exitCode !== null || child.signalCode !== null);
  } finally {
    if (child?.exitCode === null) child.kill();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
