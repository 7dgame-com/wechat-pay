# WeChat Pay public-key implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Implementation, tests and a local commit are authorized; do not push or deploy.

**Goal:** Send compatible WeChat Pay headers and return only authenticated successful response/callback facts.

**Architecture:** A serial-key resolver supports one configured public key plus an optional existing X509 platform certificate. A shared verifier authenticates raw text. All request paths reuse the existing request helper, with the original direct-path error labels retained.

**Tech Stack:** Node 22, TypeScript, node:crypto, node:http, Vitest.

- [x] Confirm clean detached deployed baseline `503acc5`; create `codex/wechat-public-key` in the task's isolated clone. Read provider boundaries and existing tests.
- [x] Run locked dependency installation and the baseline tests using `/opt/homebrew/opt/node@22/bin` first in PATH.
- [x] Add generated test-only certificate/key fixtures and real RSA signed response/callback helpers. Add behavioral tests in `tests/wechat-payment-verification.test.ts` for sequential direct requests, partner/invoice contracts, actual loopback Fetch language negotiation, key selection, rejection cases, raw body, signed 204, and verification-before-parse/decrypt.
- [x] Run `npm test` against the unchanged source, retaining the expected failing assertions in `/private/tmp/model-optimizer-payment-evidence/01-red.log`.
- [x] Update `src/wechat-native-provider.ts`: resolve exact key IDs/serials; share response/callback verification; add default headers to `wechatRequest`; route direct create/query through it with preserved error labels. Update `src/config.ts` readiness and document the existing public-key ID setting in `README.md`.
- [x] Run `npm test`, `npm run build`, and `npm run lint`; preserve logs in `/private/tmp/model-optimizer-payment-evidence/`. Confirm AES and business mappings did not change.
- [x] Obtain independent review; run `git diff --check`; hand the reviewed files to the parent for its requested final commit. No implementation-agent push or deployment.

## Verification record

Node 22.16.0; locked `npm ci` succeeded without lockfile changes. The original
six tests passed. Completed regression fixtures against unchanged production
source produced 27 expected failures and 22 passes (`01-red.log`), including
real Fetch's wildcard-language HTTP 406 and missing signature validation.
After implementation all 49 tests passed (`02-green.log`); build and lint
exited 0 (`03-build.log`, `04-lint.log`). The loopback fixture needs permission
to listen on 127.0.0.1 and makes no external requests. The existing Vite CJS
deprecation warning remains.

The parent and an independent reviewer each re-ran all 49 tests successfully;
the reviewer also confirmed no blocking issue in the source, fixtures or
provider contracts. Final diff checking passed. No real credential was read,
written or committed; RSA private-key fixtures are synthetic test data.
