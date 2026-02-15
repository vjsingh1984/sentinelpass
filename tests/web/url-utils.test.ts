import { describe, expect, it } from 'vitest';
import { normalizeLaunchUrl } from '../../sentinelpass-ui/url-utils.ts';

describe('normalizeLaunchUrl', () => {
  it('rejects empty values', () => {
    expect(() => normalizeLaunchUrl('   ')).toThrow('URL is required');
  });

  it('adds https scheme when missing', () => {
    expect(normalizeLaunchUrl('github.com/login')).toBe('https://github.com/login');
  });

  it('keeps valid https URL and normalizes trailing slash', () => {
    expect(normalizeLaunchUrl('https://github.com')).toBe('https://github.com/');
  });

  it('rejects unsupported schemes', () => {
    expect(() => normalizeLaunchUrl('javascript:alert(1)')).toThrow('Only http/https URLs are supported');
  });

  it('rejects invalid URLs', () => {
    expect(() => normalizeLaunchUrl('https://')).toThrow('Invalid URL');
  });
});
