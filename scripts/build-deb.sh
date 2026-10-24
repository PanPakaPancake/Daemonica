#!/bin/sh
# Build the daemonia .deb. Uses nfpm if installed, otherwise dpkg-deb with the
# same layout as packaging/nfpm.yaml. Artifacts are never signed here; without
# the owner's signing key (SPEC S2) they carry the -UNSIGNED-TESTONLY suffix.
set -eu

VERSION="$1"
ARCH="$2"
SUFFIX="${3:--UNSIGNED-TESTONLY}"
OUT="dist/daemonia_${VERSION}_${ARCH}${SUFFIX}.deb"

if command -v nfpm >/dev/null 2>&1; then
  ARCH="$ARCH" VERSION="$VERSION" nfpm package --config packaging/nfpm.yaml --packager deb --target "$OUT"
  echo "$OUT"
  exit 0
fi

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
chmod 0755 "$ROOT"

install -D -m 0755 "dist/$ARCH/daemonia-web"    "$ROOT/usr/bin/daemonia-web"
install -D -m 0755 "dist/$ARCH/daemonia-helper" "$ROOT/usr/bin/daemonia-helper"
install -D -m 0750 "dist/$ARCH/daemonia-admin"  "$ROOT/usr/sbin/daemonia-admin"
install -D -m 0644 packaging/systemd/daemonia-web.service    "$ROOT/usr/lib/systemd/system/daemonia-web.service"
install -D -m 0644 packaging/systemd/daemonia-helper.service "$ROOT/usr/lib/systemd/system/daemonia-helper.service"
install -D -m 0644 README.md       "$ROOT/usr/share/doc/daemonia/README.md"
install -D -m 0644 docs/INSTALL.md "$ROOT/usr/share/doc/daemonia/INSTALL.md"

install -d "$ROOT/DEBIAN"
for s in postinst prerm postrm; do
  install -m 0755 "packaging/maintainer-scripts/$s" "$ROOT/DEBIAN/$s"
done
SIZE=$(du -sk "$ROOT/usr" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: daemonia
Version: $VERSION
Architecture: $ARCH
Section: admin
Priority: optional
Maintainer: Daemonia maintainers <tnebert@gmail.com>
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
