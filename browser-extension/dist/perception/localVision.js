/**
 * Final browser-native visual inference boundary.
 *
 * Until an offline model bundle is present, this returns UNAVAILABLE. The
 * privacy pipeline must treat that state as incomplete coverage; it must never
 * silently downgrade to "no visual PII found".
 */
export async function runLocalVision(_screenshotDataUrl) {
    return {
        status: 'UNAVAILABLE',
        findings: [],
        error: 'offline browser vision model bundle is not installed yet',
    };
}
