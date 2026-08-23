function normalize(value) {
    if (Array.isArray(value))
        return value.map(normalize);
    if (value !== null && typeof value === 'object') {
        const record = value;
        const result = {};
        for (const key of Object.keys(record).sort()) {
            const item = record[key];
            if (item !== undefined)
                result[key] = normalize(item);
        }
        return result;
    }
    return value;
}
export function canonicalJson(value) {
    return JSON.stringify(normalize(value));
}
export async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(canonicalJson(value));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
