import logging
import re
import sys
from pathlib import Path

import gi
from gi.repository import Gio
from gi.repository import GLib

from .dbus_sessions import create_session
from .keyring import AccessDeniedError
from .keyring import NotFoundError

OFSP = '/org/freedesktop/secrets'
OFSI = 'org.freedesktop.Secret'

gi.require_version('Gtk', '3.0')

logger = logging.getLogger(__name__)
logging.basicConfig()

with (Path(__file__).parent / 'org.freedesktop.Secrets.xml').open() as fh:
    INFO_XML = fh.read()


class BaseDBusService:
    def __init__(self, xml):
        self.info = Gio.DBusNodeInfo.new_for_xml(xml)

    def register_object(self, conn, path, iface):
        return conn.register_object(
            path,
            self.info.lookup_interface(iface),
            self.call,
            self.get_prop,
            self.set_prop,
        )

    def on_bus_acquired(self, conn, bus, user_data=None):
        print(f'bus {bus} acquired')

    def on_name_lost(self, conn, name, user_data=None):
        sys.exit(f'Could not aquire name {name}. Is some other service blocking it?')

    def run(self, name):
        handle = Gio.bus_own_name(
            Gio.BusType.SESSION,
            name,
            Gio.BusNameOwnerFlags.NONE,
            self.on_bus_acquired,
            None,
            self.on_name_lost,
        )

        try:
            loop = GLib.MainLoop()
            loop.run()
        finally:
            Gio.bus_unown_name(handle)

    def _call(self, conn, sender, path, iface, member, args, error):
        try:
            key = iface.rsplit('.', 1)[1] + member
            key = re.sub(r'([A-Z])', r'_\1', key).strip('_').lower()
            fn = getattr(self, key)
        except AttributeError as e:
            raise GLib.Error(
                domain=Gio.dbus_error_quark(),
                code=error,
            ) from e
        try:
            return fn(conn, sender, path, *args)
        except NotFoundError as e:
            raise GLib.Error(
                domain=Gio.dbus_error_quark(),
                code=Gio.DBusError.UNKNOWN_OBJECT,
            ) from e
        except AccessDeniedError as e:
            raise GLib.Error(
                domain=Gio.dbus_error_quark(),
                code=Gio.DBusError.ACCESS_DENIED,
            ) from e
        except Exception as e:
            logger.exception(e)
            raise GLib.Error(
                domain=Gio.dbus_error_quark(),
                code=Gio.DBusError.FAILED,
            ) from e

    def call(self, conn, sender, path, iface, method, params, invocation):
        try:
            error = Gio.DBusError.UNKNOWN_METHOD
            result = self._call(conn, sender, path, iface, method, params, error)
            invocation.return_value(result)
        except GLib.Error as e:
            invocation.return_error_literal(e.domain, e.code, e.message)

    def get_prop(self, conn, sender, path, iface, prop):
        error = Gio.DBusError.UNKNOWN_PROPERTY
        return self._call(conn, sender, path, iface, f'Get{prop}', [], error)

    def set_prop(self, conn, sender, path, iface, prop, value):
        error = Gio.DBusError.UNKNOWN_PROPERTY
        self._call(conn, sender, path, iface, f'Set{prop}', [value], error)
        return True


class DBusService(BaseDBusService):
    def __init__(self, keyring):
        super().__init__(INFO_XML)
        self.keyring = keyring
        self.sessions = {}
        self.registered_items = {}
        self.session_counter = 0

    def ids_to_paths(self, items):
        return [f'{OFSP}/collection/it/{id}' for id in items]

    def update_items(self, conn, *, keep=None, add=[], rm=[]):
        for id, reg_id in list(self.registered_items.items()):
            if id in rm or (keep is not None and id not in keep):
                conn.unregister_object(reg_id)
                del self.registered_items[id]

        for id in add:
            if id not in self.registered_items:
                self.registered_items[id] = self.register_object(
                    conn,
                    f'{OFSP}/collection/it/{id}',
                    f'{OFSI}.Item',
                )

    def search_items(self, conn, query={}):
        items = self.keyring.search_items(query)
        self.update_items(conn, add=items)
        if not query:
            self.update_items(conn, keep=items)
        return items

    def on_bus_acquired(self, conn, bus):
        super().on_bus_acquired(conn, bus)
        self.register_object(conn, OFSP, f'{OFSI}.Service')
        self.register_object(conn, f'{OFSP}/aliases/default', f'{OFSI}.Collection')
        self.register_object(conn, f'{OFSP}/collection/it', f'{OFSI}.Collection')

        self.search_items(conn)

    def service_open_session(self, conn, sender, path, algorithm, input):
        output, session = create_session(algorithm, input)
        self.session_counter += 1
        session_path = f'{OFSP}/sessions/{self.session_counter}'
        self.sessions[session_path] = session
        self.register_object(conn, session_path, f'{OFSI}.Session')
        return GLib.Variant('(vo)', (GLib.Variant('ay', output), session_path))

    def service_search_items(self, conn, sender, path, query):
        items = self.search_items(conn, query)
        return GLib.Variant('(aoao)', (self.ids_to_paths(items), []))

    def service_unlock(self, conn, sender, path, objects):
        return GLib.Variant('(aoo)', (objects, '/'))

    def service_lock(self, conn, sender, path, objects):
        self.keyring.lock()
        return GLib.Variant('(aoo)', ([], '/'))

    def service_get_secrets(self, conn, sender, path, items, session_path):
        session = self.sessions[session_path]
        result = []
        for path in items:
            id = int(path.rsplit('/', 1)[1], 10)
            secret = self.keyring.get_secret(id)
            secret_tuple = session.encode(session_path, secret)
            result.append((path, secret_tuple))
        return GLib.Variant('(a{o(oayays)})', [result])

    def service_read_alias(self, conn, sender, path, name):
        if name == 'default':
            return GLib.Variant('(o)', [f'{OFSP}/collection/it'])
        else:
            return GLib.Variant('(o)', ['/'])

    def service_get_collections(self, conn, sender, path):
        return GLib.Variant('ao', [f'{OFSP}/collection/it'])

    def collection_search_items(self, conn, sender, path, query):
        items = self.search_items(conn, query)
        return GLib.Variant('(ao)', [self.ids_to_paths(items)])

    def collection_create_item(
        self, conn, sender, path, properties, secret_tuple, replace
    ):
        session = self.sessions[secret_tuple[0]]
        secret = session.decode(secret_tuple)
        attributes = properties.get(f'{OFSI}.Item.Attributes', {})
        id = None
        if replace:
            matches = self.search_items(conn, attributes)
            if matches:
                id = matches[0]
                self.keyring.update_secret(id, secret)
        if not id:
            id = self.keyring.create_item(attributes, secret)
            self.update_items(conn, add=[id])
        # TODO: trigger signal
        return GLib.Variant('(oo)', (f'{OFSP}/collection/it/{id}', '/'))

    def collection_get_items(self, conn, sender, path):
        items = self.search_items(conn)
        return GLib.Variant('ao', self.ids_to_paths(items))

    def collection_get_label(self, conn, sender, path):
        return GLib.Variant('s', 'it')

    def collection_get_created(self, conn, sender, path):
        return GLib.Variant('t', 0)

    def collection_get_modified(self, conn, sender, path):
        return GLib.Variant('t', 0)

    def collection_get_locked(self, conn, sender, path):
        return GLib.Variant('b', value=False)

    def item_delete(self, conn, sender, path):
        id = int(path.rsplit('/', 1)[1], 10)
        self.keyring.delete_item(id)
        self.update_items(conn, rm=[id])
        return GLib.Variant('(o)', ['/'])
        # TODO: trigger signal

    def item_get_secret(self, conn, sender, path, session_path):
        id = int(path.rsplit('/', 1)[1], 10)
        secret = self.keyring.get_secret(id)
        session = self.sessions[session_path]
        secret_tuple = session.encode(session_path, secret)
        return GLib.Variant('((oayays))', [secret_tuple])

    def item_set_secret(self, conn, sender, path, secret_tuple):
        id = int(path.rsplit('/', 1)[1], 10)
        session = self.sessions[secret_tuple[0]]
        secret = session.decode(secret_tuple)
        self.keyring.update_secret(id, secret)
        # TODO: trigger signal

    def item_get_label(self, conn, sender, path):
        return GLib.Variant('s', path.rsplit('/', 1)[1])

    def item_get_type(self, conn, sender, path):
        return GLib.Variant('s', f'{OFSI}.Generic')

    def item_get_created(self, conn, sender, path):
        return GLib.Variant('t', 0)

    def item_get_modified(self, conn, sender, path):
        return GLib.Variant('t', 0)

    def item_get_locked(self, conn, sender, path):
        return GLib.Variant('b', value=False)

    def item_get_attributes(self, conn, sender, path):
        id = int(path.rsplit('/', 1)[1], 10)
        attributes = self.keyring.get_attributes(id)
        return GLib.Variant('a{ss}', attributes.items())

    def item_set_attributes(self, conn, sender, path, value):
        id = int(path.rsplit('/', 1)[1], 10)
        self.keyring.update_attributes(id, value.unpack())
        # TODO: trigger signal

    def session_close(self, conn, sender, path):
        del self.sessions[path]
