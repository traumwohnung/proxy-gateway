import { runMigrations, TARGET_VERSION } from './migrations.js';

const r = await runMigrations();
if (r.applied.length === 0) {
  console.log(`[migrate] already at version ${r.to} (target ${TARGET_VERSION})`);
} else {
  console.log(`[migrate] ${r.from} -> ${r.to} (applied: ${r.applied.join(', ')})`);
}
process.exit(0);
