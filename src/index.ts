#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import { runDoctor } from './commands/doctor.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Dynamically read version from package.json
let version = '0.0.4';
try {
  const packageJsonPath = path.resolve(__dirname, '../package.json');
  const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  version = pkg.version || '0.0.4';
} catch {
  // Fallback if read fails
}

const program = new Command();

program
  .name('goat')
  .description('GOAT - Public npm launcher and coding agent client')
  .version(version, '-v, --version', 'Output the current version');

// Explicit version command to support 'goat version'
program
  .command('version')
  .description('Output the current version of the GOAT CLI')
  .action(() => {
    console.log(version);
  });

// Doctor command to support 'goat doctor'
program
  .command('doctor')
  .description('Perform a system health check to diagnose configuration and permission issues')
  .action(async () => {
    try {
      await runDoctor();
    } catch (err: any) {
      console.error('An error occurred during diagnostics:', err);
      process.exit(1);
    }
  });

// Parse command line arguments
await program.parseAsync(process.argv);
