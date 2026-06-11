// Additional secret rules curated from the Gitleaks rule catalog
// (https://github.com/gitleaks/gitleaks, MIT). These cover vendor formats that
// the core SECRET_RULES set in ./secrets-rules.ts does not — Mailchimp,
// Pulumi, Doppler, Databricks, Fly.io, CircleCI, Shippo, Terraform Cloud,
// Yandex, Duffel, NuGet, ClickUp, Grafana, Supabase, Discord webhook.
//
// Kept in a separate file so the curated/imported split stays visible and the
// core file doesn't drift into a 100-line catalog dump. Imported rules sit at
// the same priority as core rules (class "secrets"); within a class the merge
// keeps earlier+longer (see ../spans.ts), so put new rules with broader
// patterns LAST within this file.
function re(src, flags = "g") {
    return new RegExp(src, flags);
}
export const IMPORTED_SECRET_RULES = [
    {
        id: "mailchimp-api-key",
        class: "secrets",
        pattern: re("\\b([0-9a-f]{32}-us[0-9]{1,2})\\b"),
    },
    {
        id: "pulumi-access-token",
        class: "secrets",
        pattern: re("\\b(pul-[a-f0-9]{40})\\b"),
    },
    {
        id: "doppler-token",
        class: "secrets",
        pattern: re("\\b(dp\\.[a-z]{2,4}\\.[A-Za-z0-9]{40,44})\\b"),
    },
    {
        id: "databricks-token",
        class: "secrets",
        pattern: re("\\b(dapi[a-f0-9]{32})\\b"),
    },
    {
        id: "fly-io-token",
        class: "secrets",
        pattern: re("\\b(fo1_[A-Za-z0-9_\\-]{43,})\\b"),
    },
    {
        id: "circleci-personal-token",
        class: "secrets",
        pattern: re("\\b(CCI[A-Z]{2,4}_[A-Za-z0-9_]{40,})\\b"),
    },
    {
        id: "shippo-token",
        class: "secrets",
        pattern: re("\\b(shippo_(?:live|test)_[a-f0-9]{40})\\b"),
    },
    {
        id: "terraform-cloud-token",
        class: "secrets",
        pattern: re("\\b([A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_\\-]{60,})\\b"),
    },
    {
        id: "yandex-iam-token",
        class: "secrets",
        pattern: re("\\b(t1\\.[A-Za-z0-9_\\-]{20,}\\.[A-Za-z0-9_\\-]{43})\\b"),
    },
    {
        id: "yandex-oauth-token",
        class: "secrets",
        pattern: re("\\b(y0_[A-Za-z0-9_\\-]{55,})\\b"),
    },
    {
        id: "duffel-key",
        class: "secrets",
        pattern: re("\\b(duffel_(?:live|test)_[A-Za-z0-9_\\-]{40,})\\b"),
    },
    {
        id: "nuget-api-key",
        class: "secrets",
        pattern: re("\\b(oy2[a-z0-9]{43})\\b"),
    },
    {
        // ClickUp prefix `pk_` overlaps Stripe's `pk_live_/pk_test_`; the rest of
        // the format diverges (numeric then uppercase hex). Stripe rule lives in
        // the core file and runs first, so a Stripe key won't be re-classified.
        id: "clickup-token",
        class: "secrets",
        pattern: re("\\b(pk_[0-9]{6,10}_[A-Z0-9]{32})\\b"),
    },
    {
        id: "grafana-service-account-token",
        class: "secrets",
        pattern: re("\\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\\b"),
    },
    {
        id: "supabase-publishable-key",
        class: "secrets",
        pattern: re("\\b(sbp_[a-zA-Z0-9_]{40})\\b"),
    },
    {
        // Discord webhook URLs leak posting rights to the channel — treat the
        // full URL as the secret (capture group spans the whole match).
        id: "discord-webhook-url",
        class: "secrets",
        pattern: re("(https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\\-]{60,})"),
    },
];
