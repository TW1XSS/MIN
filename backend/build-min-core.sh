#!/usr/bin/env bash
#
# build-min-core.sh — сборка Rust-ядра MIN под iOS и упаковка MinCore.xcframework.
#
# Пайплайн (детерминирован, повторяем):
#   1. cargo test --workspace --release        — эталон: все тесты крейтов
#   2. кросс-сборка min-ffi под 3 iOS-таргета:
#        aarch64-apple-ios        (device, arm64)
#        aarch64-apple-ios-sim    (simulator, arm64)
#        x86_64-apple-ios         (simulator, x86_64)
#   3. lipo -create               — fat-архив simulator (x86_64 + arm64)
#   4. сборка MinCore.xcframework из срезов и статичных ассетов (Info.plist,
#      MinCore.modulemap, headers) в КОРНЕВУЮ КОПИЮ (им пользуется Xcode)
#      и в зеркало backend/MinCore.xcframework.
#
# Требуется: rustup-тулчейн с iOS-таргетами + xcode CLT (lipo).
# Запуск:  ./backend/build-min-core.sh
# Безопасно перезапускать; не требует прав администратора.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

log() { printf '\n==> %s\n' "$*"; }

cd "$BACKEND"

log "1/4  cargo test --workspace --release"
cargo test --workspace --release

log "2/4  cross-build min-ffi (3 iOS targets)"
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
# Release build: direct TCP is intentionally NOT compiled into MinCore.xcframework.
# The dev harness is available to cargo tests only; production transport is SOCKS5/Tor.
cargo build --release --target "$target" -p min-ffi
done

log "3/4  lipo: fat simulator archive"
tgt="$BACKEND/target"
[ -f "$tgt/x86_64-apple-ios/release/libmin_ffi.a" ] || { echo "missing x86_64 slice" >&2; exit 1; }
[ -f "$tgt/aarch64-apple-ios-sim/release/libmin_ffi.a" ] || { echo "missing arm64-sim slice" >&2; exit 1; }
lipo -create \
    "$tgt/x86_64-apple-ios/release/libmin_ffi.a" \
    "$tgt/aarch64-apple-ios-sim/release/libmin_ffi.a" \
    -output "$tgt/libmin_ffi_sim.a"

log "4/4  assemble MinCore.xcframework"
STAGE="$OUT/stage"
mkdir -p \
    "$STAGE/ios-arm64/Headers" \
    "$STAGE/ios-arm64_x86_64-simulator/Headers"

# --- slices ---
cp "$tgt/aarch64-apple-ios/release/libmin_ffi.a" "$STAGE/ios-arm64/libmin_ffi.a"
cp "$BACKEND/include/min_ffi.h" "$STAGE/ios-arm64/Headers/min_ffi.h"
cp "$tgt/libmin_ffi_sim.a" "$STAGE/ios-arm64_x86_64-simulator/libmin_ffi.a"
cp "$BACKEND/include/min_ffi.h" "$STAGE/ios-arm64_x86_64-simulator/Headers/min_ffi.h"

# --- статичные ассеты ---
cat > "$STAGE/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>BinaryPath</key>
			<string>libmin_ffi.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>libmin_ffi.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>BinaryPath</key>
			<string>libmin_ffi.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64_x86_64-simulator</string>
			<key>LibraryPath</key>
			<string>libmin_ffi.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
				<string>x86_64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLIST

for slice in ios-arm64 ios-arm64_x86_64-simulator; do
    cat > "$STAGE/$slice/MinCore.modulemap" <<'MODULEMAP'
module MinCoreKit {
	umbrella header "Headers/min_ffi.h"
	export *
}
MODULEMAP
done

# --- установка в корневую копию (её использует project.pbxproj) и зеркало ---
for dest in "$ROOT/MinCore.xcframework" "$BACKEND/MinCore.xcframework"; do
    mkdir -p "$dest"
    cp -R "$STAGE/." "$dest/"
done

# --- проверка: обе копии должны быть байт-в-байт идентичны ---
for rel in \
    "Info.plist" \
    "ios-arm64/libmin_ffi.a" \
    "ios-arm64/Headers/min_ffi.h" \
    "ios-arm64/MinCore.modulemap" \
    "ios-arm64_x86_64-simulator/libmin_ffi.a" \
    "ios-arm64_x86_64-simulator/Headers/min_ffi.h" \
    "ios-arm64_x86_64-simulator/MinCore.modulemap"
do
    cmp -s "$ROOT/MinCore.xcframework/$rel" "$BACKEND/MinCore.xcframework/$rel" \
        || { echo "MISMATCH: $rel" >&2; exit 1; }
done

echo "OK: MinCore.xcframework обновлён (root + backend mirror идентичны)."