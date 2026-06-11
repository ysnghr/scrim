---
description: View, validate, or edit the Scrim policy at .scrim/policy.yml.
argument-hint: "[show|validate|edit]"
---

Manage `.scrim/policy.yml` based on `$ARGUMENTS`:

- `show` (default) — print the effective policy after merging defaults
- `validate` — parse the policy and report errors with line numbers
- `edit` — open the policy file for the user to edit, then re-validate

If `.scrim/policy.yml` does not exist, offer to scaffold one from the default policy that ships with the plugin.
