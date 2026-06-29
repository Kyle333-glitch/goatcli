import os from 'os';
import path from 'path';
import fs from 'fs';

export interface EngineResolution {
  path: string | null;
  source: 'env' | 'config' | 'default' | 'none';
}

export function getAppDataDir(): string {
  const home = os.homedir();
  switch (process.platform) {
    case 'win32':
      return process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'goat')
        : path.join(home, 'AppData', 'Local', 'goat');
    case 'darwin':
      return path.join(home, 'Library', 'Application Support', 'goat');
    default:
      return process.env.XDG_DATA_HOME
        ? path.join(process.env.XDG_DATA_HOME, 'goat')
        : path.join(home, '.local', 'share', 'goat');
  }
}

export function getCacheDir(): string {
  const home = os.homedir();
  switch (process.platform) {
    case 'win32':
      return process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'goat', 'Cache')
        : path.join(home, 'AppData', 'Local', 'goat', 'Cache');
    case 'darwin':
      return path.join(home, 'Library', 'Caches', 'goat');
    default:
      return process.env.XDG_CACHE_HOME
        ? path.join(process.env.XDG_CACHE_HOME, 'goat')
        : path.join(home, '.cache', 'goat');
  }
}

export function getEnginePath(): EngineResolution {
  // 1. Env variable check
  if (process.env.GOAT_ENGINE_PATH) {
    return {
      path: path.resolve(process.env.GOAT_ENGINE_PATH),
      source: 'env',
    };
  }

  // 2. Config file check
  const appDataDir = getAppDataDir();
  const configPath = path.join(appDataDir, 'config.json');
  try {
    if (fs.existsSync(configPath)) {
      const configRaw = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(configRaw);
      // Validate to prevent prototype pollution
      if (
        config &&
        typeof config === 'object' &&
        !Array.isArray(config) &&
        Object.getPrototypeOf(config) === Object.prototype &&
        typeof config.enginePath === 'string'
      ) {
        // Resolve relative paths against the config directory for deterministic behavior
        return {
          path: path.resolve(appDataDir, config.enginePath),
          source: 'config',
        };
      }
    }
  } catch {
    // Ignore read or parse errors to fallback
  }

  // 3. Default path check
  const exeName = process.platform === 'win32' ? 'goat-engine.exe' : 'goat-engine';
  const defaultPath = path.join(appDataDir, 'bin', exeName);
  
  // We check if it exists at default path, but if not, we can still report it as default fallback
  return {
    path: defaultPath,
    source: fs.existsSync(defaultPath) ? 'default' : 'none',
  };
}
