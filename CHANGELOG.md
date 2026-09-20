# Changelog

## [0.2.2](https://github.com/coreyja-studio/pending-review-notifier/compare/v0.2.1...v0.2.2) (2026-09-20)


### Features

* declare Eyes health check for the notifier ([#21](https://github.com/coreyja-studio/pending-review-notifier/issues/21)) ([a585742](https://github.com/coreyja-studio/pending-review-notifier/commit/a5857422ea26436f34a2bee691758d9461e9b7a7))
* emit Eyes boot manifest at startup ([#19](https://github.com/coreyja-studio/pending-review-notifier/issues/19)) ([7c843fa](https://github.com/coreyja-studio/pending-review-notifier/commit/7c843fa4d79800c8d62c2900df30dbc30f9cb88b))


### Bug Fixes

* graceful shutdown via cja's Supervisor (DEV-1334) ([#22](https://github.com/coreyja-studio/pending-review-notifier/issues/22)) ([77bb9a9](https://github.com/coreyja-studio/pending-review-notifier/commit/77bb9a95d132f7c0bb02fbfe5e0cccbff9617492))
* keep eyes shutdown handle alive so eyes telemetry works ([#15](https://github.com/coreyja-studio/pending-review-notifier/issues/15)) ([72bfd19](https://github.com/coreyja-studio/pending-review-notifier/commit/72bfd19757ea4f2165830b83e44c4b73144b56fa))

## [0.2.1](https://github.com/coreyja-studio/pending-review-notifier/compare/v0.2.0...v0.2.1) (2026-07-17)


### Features

* pause reminders + List-Unsubscribe one-click ([#12](https://github.com/coreyja-studio/pending-review-notifier/issues/12)) ([c92acaa](https://github.com/coreyja-studio/pending-review-notifier/commit/c92acaa06439374148ca027a0c570a6e812ad66d))


### Bug Fixes

* send Accept header to MailPace (406 without it) ([#14](https://github.com/coreyja-studio/pending-review-notifier/issues/14)) ([72dbb07](https://github.com/coreyja-studio/pending-review-notifier/commit/72dbb0700a118a0250f2356efbc13231e47f31b4))

## [0.2.0](https://github.com/coreyja-studio/pending-review-notifier/compare/v0.1.0...v0.2.0) (2026-07-17)


### ⚠ BREAKING CHANGES

* reminder emails after your last comment, replacing the daily digest ([#10](https://github.com/coreyja-studio/pending-review-notifier/issues/10))

### Features

* cargo-binstall support + release-please automation ([#8](https://github.com/coreyja-studio/pending-review-notifier/issues/8)) ([8120822](https://github.com/coreyja-studio/pending-review-notifier/commit/812082257fddcdb5196c84b114a343d4ac1d97af))
* reminder emails after your last comment, replacing the daily digest ([#10](https://github.com/coreyja-studio/pending-review-notifier/issues/10)) ([efa16d2](https://github.com/coreyja-studio/pending-review-notifier/commit/efa16d2ae87371c3746e609fb3f9d8f8fded8ce6))
