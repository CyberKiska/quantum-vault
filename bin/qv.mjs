#!/usr/bin/env node

import { runQvCli } from '../src/core/cli/qv.js';

const exitCode = await runQvCli(process.argv.slice(2));
process.exitCode = exitCode;
