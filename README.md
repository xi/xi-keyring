# xi keyring

A simple and extensible alternative to gnome-keyring that implements
the
[`org.freedesktop.Secret`](https://specifications.freedesktop.org/secret-service/)
DBus interface and the [XDG Desktop Portal Secrets
backend](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html)
as well as a simple JSON socket interface.

## Design

### Focus on Experimentation

gnome-keyring is tightly integrated into the Linux desktop. There are many
other password managers with interesting features. Just to name a few:
[KeePassXC](https://github.com/keepassxreboot/keepassxc),
[Bitwarden](https://bitwarden.com), [pass](https://www.passwordstore.org/), and
[Himitsu](https://sr.ht/~sircmpwn/himitsu/). However, they do not all implement
the `org.freedesktop.Secret` interface, so they cannot be used as drop-in
replacements. On the other hand, gnome-keyring is so big and complex that it is
hard to experiment with new features.

The main focus of this project is to provide a simple code base that makes it
easy to experiment with new features. While the result is usable, the focus is
on experimentation rather than providing a complete product.

### Limit access to secrets

With gnome-keyring, secrets in an unlocked collection can be read by any
application that has access to the session bus. This does startle some users,
but the developers have repeatedly explained that [there is just no point in
trying to protect against malicious un-sandboxed
applications](https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/5#note_1876550).

While I understand the sentiment, I feel like there is room for nuance here.
These are some of the mechanisms xi-keyring uses to limit access to secrets:

-   Prompt the user when an application tries to access a password to provide
    some degree of observability.
-   Prevent malicious applications from taking memory dumps by using
    [`PR_SET_DUMPABLE`](https://www.man7.org/linux/man-pages/man2/prctl.2.html)
-   Keep the keyring locked as much as possible without impacting user comfort
    too much. For example, don't unlock automatically on login.
-   Allow to use different namespaces for different applications (see below for
    details)

Of course, a malicious application that is completely unrestricted can still
work around these measures, e.g. by starting a modified keyring implementation.
However, the amount of sandboxing necessary with these restrictions already in
place is greatly reduced.

### Compatibility with DBus interface

While this project aims to be a drop-in replacement for gnome-keyring, some
features of the `org.freedesktop.Secrets` interface have been simplified:

-   There is only a single collection (called "it")
    -   Trying to create or delete a collection fails
-   Whether the keyring is locked or not is not exposed
    -   All objects present themselves as unlocked
    -   The process of unlocking a keyring is transparent for the caller
    -   The `Unlock` method fails
    -   The `Lock` method still has an effect though
-   Prompts are transparent for the caller. No prompt is ever returned
-   Labels are generated automatically and cannot be changed
-   `Created`/`Modified` is always 0

### Compatibility with XDG Desktop Portal

It took me a while to understand the Secret Desktop Portal. When it finally
clicked I wrote a [blog
post](https://blog.ce9e.org/posts/2024-07-27-password-plan/) about it.

The main idea is that the backend only stores a single key for each
applications, and the application uses that key to encrypt its own secrets.

Applications that are sandboxed with flatpak can reliably be identified by this
mechanism. However, application running on the host can identify an arbitrary
app ID using the [Registry
portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html).

### Simple socket interface

One major downside of DBus is that all services share a single socket. This
means that a mount namespace has either access to all service, no services at
all, or it has to use
[xdg-dbus-proxy](https://github.com/flatpak/xdg-dbus-proxy).

From this perspective, using one socket per service is a much better approach.
That is the basic idea of
[xi-desktop-portals](https://github.com/xi/xi-desktop-portals). For the
keyring, a socket is available at `$XDG_RUNTIME_DIR/xi.portal.Secret`.

A client is included in `scripts/socket_client.py`. It has an interface similar
to the [keyring CLI](https://github.com/jaraco/keyring).

### Namespacing

xi-keyring loads the keys from a file in the client's mount namespace. This
makes it easy to give each application its own set of secrets. Simply mount a
different folder into `$XDG_DATA_HOME/xikeyring/`. *The mount namespace is the
secret namespace.*

However, you need to be careful when using proxies:

-   With flatpak, `xdg-dbus-proxy` is the immediate client, and it has full
    access to `$XDG_DATA_HOME`.
-   With portal APIs, `xdg-desktop-portal` is the immediate client, and it has
    full access to `$XDG_DATA_HOME`.

When using flatpak, I recommend using the portal APIs and their namespacing
based in app IDs.

With other sandboxing mechanisms, I recommend using the socket interface
because it allows to nest different sandboxes inside of each other and does not
require a separate proxy process.
