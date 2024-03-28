from .dbus import DBusService
from .keyring import Keyring

with Keyring('keyring.db') as keyring:
    service = DBusService(keyring)
    # service.run('org.freedesktop.secrets')
    service.run('org.ce9e.keyring')
