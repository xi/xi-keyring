pkgname='xi-keyring'
pkgver='0.0.0'
pkgdesc='simple and extensible alternative for gnome-keyring'
arch=('all')
url='https://github.com/xi/xi-keyring'
license='MIT'
depends=(
	pinentry
	python3-cryptography
	python3-gi
)

package() {
	git ls-files xikeyring | while read -r l; do
		install -Dm 644 "$l" "$pkgdir/usr/lib/python3/dist-packages/$l"
	done
	install -Dm 644 README.md "$pkgdir/usr/share/docs/xi-keyring/README.md"
	install -Dm 644 system/dbus.service "$pkgdir/usr/share/dbus-1/services/org.xi.keyring.service"
	install -Dm 644 system/systemd.service "$pkgdir/usr/lib/systemd/user/xi-keyring.service"
	install -Dm 644 system/portal "$pkgdir/usr/share/xdg-desktop-portal/portals/xi-keyring.portal"
}
