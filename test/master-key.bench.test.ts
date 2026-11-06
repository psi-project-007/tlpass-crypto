/// <reference types="vite/client" />

import {it, expect} from 'vitest';
import {deriveMasterKey} from '../src/master-key';

it.skipIf( import.meta.env.CI) ('derive in under 2 seconds', async () => {
  const t0 = performance.now();
  
  await deriveMasterKey('bench_password', 'alice@example.com');
  const t1 = performance.now() - t0;

  console.log(`deriveMasterKey: ${t1.toFixed(0)} ms`);
  expect(t1).toBeLessThan(2000);
}, 10_000);