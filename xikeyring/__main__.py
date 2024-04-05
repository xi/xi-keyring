from .dbus import DBusService
from .dumpable import pr_set
from .keyring import Keyring

pr_set(dumpable=False)

with Keyring('keyring.db') as keyring:
    service = DBusService(keyring)
    # service.run('org.freedesktop.secrets')
    service.run('org.ce9e.keyring')
