#!/bin/sh
# Build the daemonica .deb. Uses nfpm if installed, otherwise dpkg-deb with the
# same layout as packaging/nfpm.yaml. Artifacts are never signed here; without
# the owner's signing key (SPEC S2) they carry the -UNSIGNED-TESTONLY suffix.
set -eu

VERSION="$1"
ARCH="$2"
SUFFIX="${3:--UNSIGNED-TESTONLY}"
OUT="dist/daemonica_${VERSION}_${ARCH}${SUFFIX}.deb"

if command -v nfpm >/dev/null 2>&1; then
  ARCH="$ARCH" VERSION="$VERSION" nfpm package --config packaging/nfpm.yaml --packager deb --target "$OUT"
  echo "$OUT"
  exit 0
fi

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
chmod 0755 "$ROOT"

install -D -m 0755 "dist/$ARCH/daemonica-web"    "$ROOT/usr/bin/daemonica-web"
install -D -m 0755 "dist/$ARCH/daemonica-helper" "$ROOT/usr/bin/daemonica-helper"
install -D -m 0750 "dist/$ARCH/daemonica-admin"  "$ROOT/usr/sbin/daemonica-admin"
install -D -m 0644 packaging/systemd/daemonica-web.service    "$ROOT/usr/lib/systemd/system/daemonica-web.service"
install -D -m 0644 packaging/systemd/daemonica-helper.service "$ROOT/usr/lib/systemd/system/daemonica-helper.service"
install -D -m 0644 README.md       "$ROOT/usr/share/doc/daemonica/README.md"
install -D -m 0644 docs/INSTALL.md "$ROOT/usr/share/doc/daemonica/INSTALL.md"

install -d "$ROOT/DEBIAN"
for s in postinst prerm postrm; do
  install -m 0755 "packaging/maintainer-scripts/$s" "$ROOT/DEBIAN/$s"
done
SIZE=$(du -sk "$ROOT/usr" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: daemonica
Version: $VERSION
Architecture: $ARCH
Section: admin
Priority: optional
Maintainer: Daemonica maintainers <tnebert@gmail.com>
Installed-Size: $SIZE
Depends: systemd, adduser
Recommends: ufw, tcpdump
Homepage: https://github.com/PanPakaPancake/daemonica
Description: Web-based administration dashboard for a single Debian/Ubuntu server
 Passkey-only login, privilege-separated helper, tamper-evident audit log.
EOF

# Reproducible timestamps.
find "$ROOT" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT" >/dev/null
echo "$OUT"
