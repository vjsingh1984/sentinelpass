/**
 * Normalise a raw URL string for launching in the system browser.
 *
 * Prepends `https://` when no scheme is present and validates that the
 * result is a well-formed `http:` or `https:` URL.
 *
 * @param rawUrl - The user-supplied URL string (may omit scheme).
 * @returns The normalised, fully-qualified URL string.
 * @throws {Error} If the input is empty, unparseable, or uses a non-HTTP scheme.
 */
export function normalizeLaunchUrl(rawUrl: string): string {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) {
    throw new Error('URL is required');
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  const candidate = hasScheme ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('Invalid URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http/https URLs are supported');
  }

  return parsed.toString();
}
