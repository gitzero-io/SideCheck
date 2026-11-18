# SideCheck by Bastion Security

An app checker for Android TV / Google TV, built for people who sideload apps and have turned off
Google Play Protect. SideCheck looks at installed apps (and APK files before you install them),
explains in plain language what each one can do, gives a grade and a recommendation — and then
**lets the user decide**.

> App ID: `com.bastionsecurity.sidecheck` · minSdk 26 (Android 8) · targetSdk 37 · Kotlin + Compose for TV

## Product rules (enforced in code and copy)

1. **Never decide for the user.** Every finding offers Keep and Remove. "Keep" is remembered and
   respected — no repeat nags. Choices are keyed by *package + signing certificate*, so they reset
   only if the app is replaced by one signed by someone else.
2. **Evidence, not verdicts.** Findings say what the app *can do*; "Details" shows the raw evidence.
3. **Grade fairly.** Being sideloaded or modified never costs points (see `Grader.kt`).
4. **Plain language.** ~8th-grade reading level; jargon only behind "Details".
5. **Privacy.** No analytics, no ads, **no `INTERNET` permission** in v1.

## Project layout

```
engine/   Pure Kotlin/JVM — no Android. Unit-tested; reusable on a server later.
  model/        AppFacts (input), Finding / AppReport (output)
  dex/          Streaming dex string-table reader + signal collector
  apk/          APK zip inspector (native libs, packers, dex files, SHA-256)
  trackers/     Tracker catalog + prefix matcher (Exodus-compatible shape)
  impersonation/ Known-brand / system-name impersonation check
  rules/        Data-driven rule engine: signals (Kotlin) + rules (JSON)
  grading/      Transparent score → A–F, and the "Our take" line
  providers/    ReputationProvider, RuleSetProvider, PremiumFeatures (future hooks)
  src/main/resources/sidecheck/
                rules.json, trackers.json, known_apps.json, packers.json

app/      Android TV app
  collect/      PackageManager → AppFacts
  data/         Scan results, Keep/Trust (DataStore), background-watch bookkeeping
  grants/       What each app is allowed to do + Shizuku bridge + Settings deep links
  install/      APK staging (copy to cache) and hand-off to the system installer
  work/         Background change detection, WorkManager job, notifications
  ui/           Compose for TV screens (home, results, detail, pick, apk check, report)
  src/debug/    Debug-only "check now" trigger (not in release builds)
```

## Build and test

Android Studio bundles the JDK; from a terminal on the Mac use it explicitly:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
./gradlew :engine:test          # engine unit tests (dex parser, rules, grading, impersonation)
./gradlew :app:assembleDebug    # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:lintDebug
```

## Running on an Onn Google TV box (from a Mac over ADB)

On the box: **Settings → System → About → Android TV OS build** (press OK 7 times) to unlock
Developer options, then **Settings → System → Developer options → USB debugging / Network debugging** on.
Find the box's IP in **Settings → Network & Internet**.

```bash
ADB=~/Library/Android/sdk/platform-tools/adb

$ADB connect 192.168.1.50:5555            # accept the prompt on the TV the first time
$ADB devices

# Install / update / launch
$ADB install -r app/build/outputs/apk/debug/app-debug.apk
$ADB shell am start -n com.bastionsecurity.sidecheck/.MainActivity

# Logs
$ADB logcat -s SideCheck:* AndroidRuntime:E

# Run the background check now (debug builds only) instead of waiting for the hourly job
$ADB shell am broadcast -a com.bastionsecurity.sidecheck.debug.CHECK_NOW -p com.bastionsecurity.sidecheck

# Check an APK the way Downloader / a file manager would ("Open with SideCheck")
$ADB push some-app.apk /sdcard/Download/
#   then open it from a file manager on the TV and choose "Check with SideCheck"

# Uninstall SideCheck
$ADB uninstall com.bastionsecurity.sidecheck
```

## How grading works

Start at 100. Each finding subtracts points by severity: INFO 0 · LOW 3 · MEDIUM 8 · HIGH 20 ·
CRITICAL 40. A finding already counted inside a combined finding (e.g. "accessibility service" inside
"accessibility + overlay + starts at boot") costs nothing extra.
Score → grade: **A ≥ 90 · B ≥ 75 · C ≥ 55 · D ≥ 35 · F < 35**, with caps so one serious problem
can't hide: any MEDIUM → at best B, any HIGH → at best C, any CRITICAL → at best D.
The app shows this breakdown under "Select to see how we graded".

## Editing rules

Rules live in `engine/src/main/resources/sidecheck/rules.json`. Each rule combines named
**signals** (defined in `rules/Signals.kt`) with simple conditions:

```json
{
  "id": "accessibility_overlay_boot",
  "severity": "HIGH", "category": "DEVICE_CONTROL", "action": "CONSIDER_REMOVING",
  "title": "Can read your screen, draw over it, and start by itself",
  "explanation": "{app} can read what's on your screen, ...",
  "why": "...",
  "when": { "all": ["accessibility", "overlay", "boot"] },
  "supersedes": ["accessibility_service", "overlay_permission", "boot_start"]
}
```

`when` supports `all`, `any`, `none` (signal names), `anyPermission`, `targetSdkBelow`,
`targetSdkAtLeast`. Template placeholders (`{app}`, `{brand}`, `{trackers}`, …) are listed at the top
of `Signals.kt`. A rule that names an unknown signal is skipped (so a downloaded rule set can't
crash an older app). Tests check that every bundled rule is supported and every template fills.

## Data files

| File | What | Notes |
|---|---|---|
| `trackers.json` | Ad/analytics SDK package prefixes | Same shape as Exodus Privacy. To import Exodus: split each `code_signature` regex on `\|`, strip escapes, map to `codeSignatures`. |
| `known_apps.json` | Brand → official package names | `signingCertSha256` is **empty on purpose** — see TODO below. |
| `packers.json` | Packer/protector native library globs | Name-based only; custom names won't be caught. |

## Known-malware list (botnets)

SideCheck bundles an offline list of known-malware **APK SHA-256** and **signing-certificate
SHA-256** hashes (`engine/src/main/resources/sidecheck/malware_db.json`).
- A sideloaded app or APK file that matches gets a CRITICAL finding and is always graded **F**
  ("This exact app is known malware" / "Made by the people behind known malware").
- **Preinstalled (firmware) apps** are checked against the list only — no grading. Botnets such
  as BadBox 2.0 and Vo1d often ship inside cheap boxes' firmware. A match shows a warning on
  Home and a "Built-in apps that match known malware" screen with "Turn off" (via Shizuku or the
  app's Settings page). System APKs over 128 MB aren't file-hashed (certificate matching still applies).
- Every entry cites its source. The list is compiled by `tools/malware-db/build_malware_db.py`,
  which only includes sources listed in `tools/malware-db/cleared_sources.txt`.
  It currently ships ESET's Android hashes (BSD-2-Clause, credited in `NOTICE`); the TV botnet
  families (Vo1d, Kimwolf, …) need permission from their publishers first — see `tools/malware-db/README.md`.
- No internet: the list updates when a new SideCheck version is published.

## Permissions SideCheck asks for

| Permission | Why |
|---|---|
| `QUERY_ALL_PACKAGES` | See and check every installed app. (Fine outside Play; Play would require a declaration.) |
| `REQUEST_INSTALL_PACKAGES` | "Install anyway" hands the checked APK to Android's installer. |
| `REQUEST_DELETE_PACKAGES` | "Remove" opens Android's uninstall dialog. |
| `POST_NOTIFICATIONS` | "New app installed: X — Grade D". Asked once on Android 13+. |

No `INTERNET`. Shizuku's provider is declared for the optional power-user mode below.

## Background protection

- Uses `PackageManager.getChangedPackages(sequence)`, remembering its place. The sequence resets on
  reboot; SideCheck detects that via `Settings.Global.BOOT_COUNT`. A second pass compares each app's
  last-update time with the last check, to catch anything missed. (Manifest `PACKAGE_ADDED`
  receivers don't work on modern Android, so they aren't used.)
- Runs hourly via WorkManager and whenever SideCheck is opened. Only changed apps are re-read.
- Notifies for: new installs; an app replaced by a different signer; an update that got a worse
  grade; an update to a never-graded app that needs attention. Never for apps the user trusted.
- **Google TV shows no pop-up notifications**; they go to Settings → Notifications. That's why Home
  also shows "New since you last looked".

## Changing other apps' permissions

Android doesn't let normal apps grant/revoke other apps' permissions. SideCheck:
- **Always** shows what each app is allowed to do (runtime permissions + special access) and offers
  "Change in Settings" (only for Settings screens that exist on this device).
- **With [Shizuku](https://github.com/RikkaApps/Shizuku)** running and approved, turns runtime
  permissions and app-ops (overlay, install apps, usage access, system settings) on/off directly.
  Accessibility, notification access and device admin always go through Settings.
- Not built: a **device-owner** mode (possible for boxes provisioned over ADB before setup) — an
  option for boxes you sell preinstalled.

## Known limits

- Dex scanning reads string tables only. Findings marked **Hint** (dynamic code loading, reflection,
  runtime exec, hard-coded IPs) show the code is present, not that it's used.
- `usesCleartextTraffic` is read from the manifest flag; network-security-config per-domain rules
  aren't parsed.
- APK bundles (.apks / .xapk / .apkm) aren't supported — single .apk only.
- "Hidden app" checks need the app installed (launcher entries can't be resolved for archives).
- Very large apps are scanned up to safety limits (time, bytes, strings); the report says so.

## Prepared for later (not built)

- `ReputationProvider` — v1 uses the bundled known-malware list; a cloud lookup (own backend,
  MalwareBazaar, VirusTotal) can be layered on later, e.g. as a premium feature.
- `RuleSetProvider` — download signed rule/tracker/known-app bundles between releases. v1: bundled.
- `PremiumFeatures` — free/paid gate. v1: `FreeTier`, everything off.
- **VPN recommendation** (referral, not a VPN in SideCheck): must be labeled as a paid referral,
  must never influence the grade of any VPN app, and needs no internet (link/QR only).

## Release signing

Release builds are signed when `keystore.properties` exists in the project root (it is
git-ignored). It points at the keystore, which lives **outside** the project:

```properties
storeFile=/Users/<you>/Keys/BastionSecurity/sidecheck-release.jks
storePassword=...
keyAlias=sidecheck
keyPassword=...
```

- Key: RSA 4096, alias `sidecheck`, valid 30 years, signed with APK Signature Scheme v2 + v3
  (v3 allows rotating to a new key later without forcing users to uninstall).
- Certificate: `CN=Bastion Security, OU=SideCheck, O=Bastion Security, C=US`
- Certificate SHA-256: `59d9d14f0894305ea0e25503b95040b983dc82c8748852966a1a922db2b04e9f`
  (publish this so users can verify downloads are really yours)

```bash
./gradlew :app:assembleRelease     # → app/build/outputs/apk/release/app-release.apk
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
```

Without `keystore.properties` (e.g. on another machine), release builds come out unsigned.

## TODO before shipping

- [ ] **Developer verification.** Google is rolling out developer verification for apps installed on
      certified Android devices, including sideloaded ones; the US is expected to follow in 2027.
      Verify the Bastion Security developer account and register `com.bastionsecurity.sidecheck`
      so SideCheck itself installs without friction.
- [x] **Release signing.** Set up (see "Release signing" below). **Back up the keystore and its
      password in two places** — losing either means existing installs can never be updated.
- [ ] **Verified certificate hashes** in `known_apps.json` → `signingCertSha256`. Only from APKs you
      trust (e.g. installed from Google Play), via `apksigner verify --print-certs`. Never guess.
- [ ] **Fill the known-malware list**: clear at least one source (e.g. ask Nokia Deepfield for
      permission, or confirm abuse.ch MalwareBazaar's terms), then run the build script.
- [ ] Replace the bundled tracker list with the Exodus Privacy list (check its license terms).
- [ ] Turn on R8 for release (`optimization.enable = true`) and keep the Shizuku rule in
      `app/src/main/keepRules/rules.keep`; test the release build on a box.
- [ ] Move UI strings to `strings.xml` before translating.

## License

SideCheck is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License, version 3, as published by the Free Software Foundation. See
[LICENSE](LICENSE).

Copyright (C) 2026 Bastion Security.

Contributions are accepted under the Contributor License Agreement in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Trademarks

The GPL covers the code, not the names. "SideCheck", "Bastion Security", and their logos are
trademarks of Bastion Security. If you distribute a modified version, give it a different
name and icon, and don't suggest it comes from or is endorsed by Bastion Security.
