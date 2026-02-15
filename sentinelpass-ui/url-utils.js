export function normalizeLaunchUrl(rawUrl) {
    const trimmed = String(rawUrl || '').trim();
    if (!trimmed) {
        throw new Error('URL is required');
    }
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
    const candidate = hasScheme ? trimmed : `https://${trimmed}`;
    let parsed;
    try {
        parsed = new URL(candidate);
    }
    catch {
        throw new Error('Invalid URL');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only http/https URLs are supported');
    }
    return parsed.toString();
}
