# drifty

Context-aware AI time tracker for Mac and Windows.

drifty helps you understand where your day actually went by classifying desktop activity as Focus, Neutral, or Drift.

Website: [https://drifty.so](https://drifty.so)

## About this repository

This public repository contains signed release downloads, concise public release notes, and issue tracking for the drifty Mac and Windows apps. The application source code is private.

## Downloads

Download the current installer from [drifty.so/download](https://drifty.so/download/). Mac downloads use a signed and notarized DMG. Windows downloads use an Authenticode-signed NSIS installer for 64-bit Windows 10 and 11.

Public release history begins at 1.6.0. Retained older versions are unsupported rollback records. Developer release candidates may appear as updater-only numbered prereleases and are not manual download choices.

## Release channels

- Mac stable: numbered GitHub Releases with user-facing notes. Only the latest stable release is supported and promoted.
- Windows stable: signed `x.y.z-win` releases are selected through [`latest-windows.json`](latest-windows.json) and the public download page.
- Developer candidates: [`latest-prerelease.json`](latest-prerelease.json) and [`latest-windows-prerelease.json`](latest-windows-prerelease.json) point to signed updater-only assets. They are not manual-download channels.
- Legacy candidate channel: the immutable `pre-release-channel` release is retained for historical clients and is no longer updated.
- Internal and test builds: private short-lived artifacts; never published here.

## Feedback

If you find a bug or have a feature request, please open an issue.
