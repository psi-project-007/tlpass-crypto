import { describe, it, expect } from 'vitest';
import { VERSION } from '../src/index';

describe('package', () => {
  it('exports its version', () => {
    expect(VERSION).toBe('0.1.0');
  });
});