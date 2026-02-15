import { describe, expect, it } from 'vitest';
import {
  buildSaveNotificationRequestKey,
  domainMatchesPolicy,
  isUsernameMatchOrUnknown,
  normalizeCredentialUrl,
  normalizeDomainForPolicy,
  normalizeUsername
} from '../../browser-extension/chrome/save-heuristics.ts';

describe('save heuristics', () => {
  it('normalizes usernames', () => {
    expect(normalizeUsername('  USER@Example.COM ')).toBe('user@example.com');
    expect(normalizeUsername(null)).toBe('');
  });

  it('normalizes policy domains', () => {
    expect(normalizeDomainForPolicy('https://www.GitHub.com/login')).toBe('github.com');
    expect(normalizeDomainForPolicy('..example.com..')).toBe('example.com');
    expect(normalizeDomainForPolicy('   ')).toBeNull();
    expect(normalizeDomainForPolicy('https://')).toBe('https://');
  });

  it('matches policy domains for subdomains', () => {
    expect(domainMatchesPolicy('app.github.com', 'github.com')).toBe(true);
    expect(domainMatchesPolicy('github.com', 'github.com')).toBe(true);
    expect(domainMatchesPolicy('github.com', 'example.com')).toBe(false);
  });

  it('normalizes credential URL to origin', () => {
    expect(normalizeCredentialUrl('https://github.com/login?x=1', '')).toBe('https://github.com');
    expect(normalizeCredentialUrl('github.com/login', '')).toBe('https://github.com');
    expect(normalizeCredentialUrl('', 'github.com')).toBe('https://github.com');
    expect(normalizeCredentialUrl('ftp://github.com/repo', 'github.com')).toBe('https://github.com');
    expect(normalizeCredentialUrl('://invalid', '')).toBeNull();
  });

  it('builds stable save notification dedupe key', () => {
    expect(
      buildSaveNotificationRequestKey({
        domain: 'github.com',
        username: ' User@Example.com ',
        url: 'https://github.com/login#section',
        password: 'secret123'
      })
    ).toBe('github.com|user@example.com|https://github.com/login|len:9');
  });

  it('handles username match or unknown semantics', () => {
    expect(isUsernameMatchOrUnknown('', 'user@example.com')).toBe(true);
    expect(isUsernameMatchOrUnknown('user@example.com', '')).toBe(true);
    expect(isUsernameMatchOrUnknown('a@example.com', 'a@example.com')).toBe(true);
    expect(isUsernameMatchOrUnknown('a@example.com', 'b@example.com')).toBe(false);
  });
});
