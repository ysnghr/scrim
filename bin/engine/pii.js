// Fast PII regex tier. Default-on per policy. Cheap to run.
//
// Covers email, US SSN, credit card (Luhn-validated), and international phone.
// Names/addresses/freeform PII are out of scope here — those need the optional
// Presidio NER tier (see presidio.ts).
const EMAIL = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const SSN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const CARD = /\b(?:\d[ \-]?){13,19}\b/g;
const PHONE = /(?:\+?\d{1,3}[ \-.]?)?(?:\(\d{3}\)|\d{3})[ \-.]?\d{3}[ \-.]?\d{4}\b/g;
function luhn(num) {
    const digits = num.replace(/[^\d]/g, "");
    if (digits.length < 13 || digits.length > 19)
        return false;
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (alt) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
        alt = !alt;
    }
    return sum % 10 === 0;
}
function scan(text, re, klass, ruleId, accept) {
    const out = [];
    const compiled = new RegExp(re.source, re.flags);
    let m;
    while ((m = compiled.exec(text)) !== null) {
        const value = m[0];
        if (!value) {
            if (m.index === compiled.lastIndex)
                compiled.lastIndex++;
            continue;
        }
        if (accept && !accept(value))
            continue;
        out.push({ start: m.index, end: m.index + value.length, class: klass, ruleId });
    }
    return out;
}
export function detectFastPii(text, allowlist) {
    const all = [
        ...scan(text, EMAIL, "pii_customer", "pii-email"),
        ...scan(text, SSN, "pii_customer", "pii-ssn"),
        ...scan(text, CARD, "pii_customer", "pii-card", luhn),
        ...scan(text, PHONE, "pii_customer", "pii-phone"),
    ];
    return all.filter((s) => !allowlist.has(text.slice(s.start, s.end)));
}
