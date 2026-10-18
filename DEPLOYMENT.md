# Hifz V5.1 deployment

The branded website is published only from `MaktabForlife/Hifz`. The original
`Hifzhelper-app/Hifzhelper` repository remains unbranded; do not publish branded
releases to either of its branches.

## Production website

- Cloudflare Pages project: `maktab-hifz`, in the existing Academy/MaktabForlife
  Cloudflare account (`c9a3e355b3d7a795880b1d36a1dbe123`).
- Git repository/production branch: `MaktabForlife/Hifz`, `main`.
- Public domain: `https://hifz.maktab4life.org/`.
- Pages hostname: `https://maktab-hifz.pages.dev/`.
- Build output directory: `public`.
- Build command:

```sh
mkdir -p public && cp -R index.html manifest.json _headers _redirects css js shared appicons assets public/
```

Only browser assets are published. Worker source, migrations, tests and private
operational files are excluded from the website output.

## API and data separation

Static hosting adds no Academy database binding. Both Hifz API Workers and both
Hifz D1 databases stay in the separate Hifz Cloudflare account
(`7f42bd46597bab9181b7a128a695f2cd`). Production uses `hifzhelper-api` with
`hifzhelper-maktab1`; development uses `hifzhelper-api-dev` with
`hifzhelper-maktab1-dev`. Deploy the matching environment from
`worker/wrangler.jsonc`, preserving existing secrets.

`hifzhelper-dev.pages.dev` remains the original development website. The production
custom domain is no longer attached to that project. Its unbranded repository is
not updated by branded releases. The owned repository retains `dev` for branded
development and previews.

Academy V107.2 (`devrebootworker`, the currently used Academy API) sends automatic
profile and PIN updates to the production Hifz receiver. Its separate fixed
development handoff endpoint is retained for development entry. Do not change the
unrelated `rebootworker` or its data during this rollout.

## PIN migration and verification

Existing journal ownership has been mapped to verified immutable Academy user
IDs. Login aliases remain editable only in Academy. Existing legacy PIN hashes
cannot be converted without the PIN: successful Academy PIN login upgrades the
credential and delivers the exact secure record to Hifz. New/reset PINs are
chosen and confirmed once in Academy; authenticated Academy entry needs no second
Hifz PIN. Direct Hifz login verifies the shared PIN locally.

The production rollout preserved 461 journal rows across 11 tables, with no
foreign-key violations. Live temporary-account checks cover identical credential
delivery, confirmed PIN setup, handoff replay rejection, direct Hifz PIN entry,
automatic PIN reset delivery and session revocation. No real user's PIN is reset
for verification.
