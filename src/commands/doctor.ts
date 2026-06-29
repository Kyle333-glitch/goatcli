import { intro, outro, spinner, note, log } from '@clack/prompts';
import fs from 'fs';
import path from 'path';
import { getAppDataDir, getCacheDir, getEnginePath } from '../utils/paths.js';
import {
  getGitVersion,
  getShell,
  checkDirectoryWritable,
  getWindowsLongPathsEnabled,
  checkPathLengthProblems,
  checkMacExecutable,
  checkWindowsPathProblems,
} from '../utils/system.js';

export async function runDoctor(): Promise<void> {
  intro('GOAT System Diagnostics (Doctor)');

  const s = spinner();
  s.start('Inspecting system environment...');

  // 1. Gather basic system information
  const osPlatform = process.platform;
  const osArch = process.arch;
  const nodeVersion = process.version;
  const cwd = process.cwd();
  const shell = getShell();
  const gitVersion = await getGitVersion();

  // 2. Resolve configured engine paths
  const engineResolution = getEnginePath();
  const appDataDir = getAppDataDir();
  const cacheDir = getCacheDir();

  // 3. Inspect writable directories
  const appDataWritable = checkDirectoryWritable(appDataDir);
  const cacheWritable = checkDirectoryWritable(cacheDir);

  // 4. Check path length constraints
  const pathsToCheck = [
    { name: 'Application Data Directory', path: appDataDir },
    { name: 'Cache Directory', path: cacheDir },
  ];
  if (engineResolution.path) {
    pathsToCheck.push({ name: 'Engine Executable Path', path: engineResolution.path });
  }
  const pathLengthStatuses = checkPathLengthProblems(pathsToCheck);

  // 5. Check platform-specific problems
  let windowsIssues = null;
  let macStatus = null;
  let longPathsEnabled: boolean | null = null;

  if (osPlatform === 'win32') {
    windowsIssues = checkWindowsPathProblems();
    longPathsEnabled = await getWindowsLongPathsEnabled();
  } else if (osPlatform === 'darwin') {
    if (engineResolution.path) {
      macStatus = await checkMacExecutable(engineResolution.path);
    }
  }

  // 6. Check engine executable status
  let engineExists = false;
  if (engineResolution.path) {
    engineExists = fs.existsSync(engineResolution.path);
  }

  s.stop('Diagnostics completed.');

  // Render System Information Note
  const sysInfoContent = [
    `• OS & Arch:       ${osPlatform} (${osArch})`,
    `• Node.js Version:  ${nodeVersion}`,
    `• Git Version:      ${gitVersion ? gitVersion : '⚠️ NOT FOUND (Git is required for many features)'}`,
    `• Shell:            ${shell}`,
    `• Working Dir:      ${cwd}`,
  ].join('\n');
  note(sysInfoContent, 'System Information');

  // Render Engine & Paths Note
  const hasEngineSpaces = osPlatform === 'win32' && engineResolution.path && engineResolution.path.includes(' ');
  const engineStatusText = engineResolution.path
    ? `${engineResolution.path} (${engineExists ? '✅ Available' : '❌ Not Found'})`
    : '❌ Not Configured';

  const pathsContent = [
    `• App Data Dir:     ${appDataDir} (${appDataWritable.writable ? '✅ Writable' : '❌ Read-Only'}${appDataWritable.exists ? ', Exists' : ', Will create'})`,
    `• Cache Dir:        ${cacheDir} (${cacheWritable.writable ? '✅ Writable' : '❌ Read-Only'}${cacheWritable.exists ? ', Exists' : ', Will create'})`,
    `• Engine Path:      ${engineStatusText}`,
    `• Path Source:      ${engineResolution.source === 'env' ? 'Environment variable (GOAT_ENGINE_PATH)' : engineResolution.source === 'config' ? 'Config file (config.json)' : engineResolution.source === 'default' ? 'Default AppData location' : 'None'}`,
  ].join('\n');
  note(pathsContent, 'GOAT Configuration & Writable Paths');

  // Diagnostic checklist and recommendations
  const warnings: string[] = [];
  const errors: string[] = [];

  // Git check
  if (!gitVersion) {
    errors.push('Git is not installed or not available in the system PATH. Please install Git.');
  }

  // Writable checks
  if (!appDataWritable.writable) {
    errors.push(`Application data directory is not writable: ${appDataWritable.error || 'Permission Denied'}`);
  }
  if (!cacheWritable.writable) {
    errors.push(`Cache directory is not writable: ${cacheWritable.error || 'Permission Denied'}`);
  }

  // Path length checks
  pathLengthStatuses.forEach((p) => {
    if (p.hasProblem) {
      warnings.push(`Path is too long (> 260 chars) on Windows and may cause issues: ${p.name} (${p.path})`);
    }
  });

  // Windows checks
  if (osPlatform === 'win32') {
    if (longPathsEnabled === false) {
      warnings.push('Windows Registry "LongPathsEnabled" is disabled. Path operations longer than 260 characters might fail.');
    }
    if (windowsIssues) {
      if (!windowsIssues.pathExtHasExe) {
        errors.push('PATHEXT environment variable does not contain ".EXE". Windows might fail to launch executables.');
      }
      if (!windowsIssues.npmBinInPath) {
        warnings.push('npm global binaries directory not detected in PATH. You may not be able to run "goat" globally.');
      }
      if (hasEngineSpaces) {
        warnings.push('Engine path contains spaces. Quoting might be required when spawning the process.');
      }
    }
  }

  // macOS / Darwin checks
  if (osPlatform === 'darwin' && engineResolution.path && engineExists) {
    if (macStatus) {
      if (!macStatus.isExecutable) {
        errors.push(`Engine binary lacks owner execution permissions. Run: chmod +x "${engineResolution.path}"`);
      }
      if (macStatus.isQuarantined) {
        warnings.push(`Engine binary is quarantined by macOS Gatekeeper. Run: xattr -d com.apple.quarantine "${engineResolution.path}"`);
      }
      if (!macStatus.codeSignValid) {
        warnings.push(`Engine binary signature verification failed. The binary may be unsigned or modified.`);
      }
    }
  }

  // Engine not configured/found check
  if (!engineResolution.path || !engineExists) {
    warnings.push(
      'GOAT engine executable is not configured or not found. Please set GOAT_ENGINE_PATH or install the engine.'
    );
  }

  // Print Issues & Outro
  if (errors.length > 0 || warnings.length > 0) {
    if (errors.length > 0) {
      log.error('Issues Detected (Critical):');
      errors.forEach((e) => log.error(`  - ${e}`));
    }
    if (warnings.length > 0) {
      log.warn('Recommendations (Warnings):');
      warnings.forEach((w) => log.warn(`  - ${w}`));
    }
    
    outro('GOAT Doctor run finished with some warnings/errors. See recommendations above.');
  } else {
    log.success('All system checks passed successfully!');
    outro('GOAT Doctor found no issues. Your environment is healthy! 🐐');
  }
}
