# Contributing to MIN

## Scope and safety

Do not include real private keys, message plaintext, onion private keys, Wi-Fi
passwords, SSH private keys, personal addresses, or production data in commits,
issues, screenshots, logs, or test fixtures. Use synthetic keys and a local relay.

The wire specification is `backend/PROTOCOL.md`. Any intentional change to §0–§10
requires a protocol-version decision and an explicit compatibility plan.

## Prerequisites

- macOS with Xcode (iOS 15+ deployment target for the current client);
- Rust toolchain and the pinned workspace dependencies;
- CocoaPods (`pod install` from the repository root);
- a local/test relay for integration tests. Never use the production Pi for
  destructive tests.

## Basic checks

```bash
# 1. Rust core tests
cd backend
cargo fmt --all
cargo test --workspace

# 2. THE CORE MUST BE BUILT BEFORE THE APP. MinCore.xcframework is NOT in Git
#    (it is ~58 MB of binaries). Skipping this step makes the linker fail with
#    `-lmin_ffi` not found — the most common first-build mistake.
cd ..
./backend/build-min-core.sh

# 3. Only then the app: Tor/IPtProxy come from CocoaPods and resolve through
#    the WORKSPACE. Building MIN.xcodeproj directly fails with
#    "No such module 'Tor'".
pod install
xcodebuild -workspace MIN.xcworkspace -scheme MIN \
  -destination 'platform=iOS Simulator,name=iPhone 17' build
```

Step 2 is needed once per checkout; rerun it after changing the FFI layer.
The release core is built without the `dev-tcp-link` feature. Direct TCP is
for tests/development only; the shipped client must use SOCKS5/Tor.

### Pointing the build at a relay

The relay endpoint lives in `MIN/Info.plist` (`MinRelayAddress`). Do not edit
that file in Git — use the helper, which injects the address into the built
`.app` and changes nothing in the repository:

```bash
MIN_RELAY_ADDR='<public-relay>.onion:3001' scripts/build-local.sh
```

Note: passing `MIN_RELAY_ADDR=` straight to `xcodebuild` does nothing — it is
a variable of the helper script, not a build setting of the Xcode project.

`MIN_RELAY_ADDR` is the public onion address only. Never put an onion private
key, SSH key, LAN credential or production secret in that value or in Git.

The repository ships `MIN_RELAY_ADDR = ""` on purpose. A relay address baked
into a tracked file would tie every fork, mirror and bug report to one specific
infrastructure node. Pass it per build, or locally in an untracked
`Local.xcconfig`, or set `min.relay` in `UserDefaults`. With no address the app
fails closed with an explicit error instead of guessing a route.

There is no supported Docker build for the iOS app yet: Xcode, CocoaPods and
Rust Apple targets require a macOS toolchain. A relay/CI container may be added
later, but it is not a substitute for the iOS build.

Do not edit `MinCore.xcframework` by hand. Rebuild it through
`backend/build-min-core.sh` when the Rust FFI changes.

## Changes

Keep one logical change per commit. Add regression tests for security and protocol
changes. Do not weaken strict parsers, rate limits, TTL enforcement, fail-closed
behaviour, or Tor-only production routing to make a test pass.

UI changes belong in the SwiftUI layer and should preserve the existing theme and
keyboard/scroll invariants. The full internal invariants are available to the
project owners and are not included in a public export.
