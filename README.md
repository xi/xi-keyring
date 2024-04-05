# xi keyring

a simple and extensible alternative for gnome-keyring.

gnome-keyring is tightly integrated into the linux desktop. There are many
other password managers with interesting features. Just to name a few:
[KeePassXC](https://github.com/keepassxreboot/keepassxc),
[Bitwarden](https://bitwarden.com), [pass](https://www.passwordstore.org/), and
[Himitsu](https://sr.ht/~sircmpwn/himitsu/). Unfortunately, none of them really
implement the `org.freedesktop.Secrets` dbus specification, so they cannot
completely replace gnome-keyring. On the other hand, gnome-keyring itself has
accumulated a sizable legacy, which makes it very hard to extend.

So this project tries to fill the gap:

-   Work as a drop-in replacement for gnome-keyring for most common use cases
-   Keep the code simple and extensible
-   Experiment with new features

## Threat model

*As the main focus for now is experimentation, there is no fixed threat model
yet. There are some ideas though.*

With gnome-keyring, secrets in an unlocked collection can be read by a
malicious application that is running on the user's desktop. This does startle
some users, but the developers have repeatedly explained that [there is just no
point in trying to protect against malicious un-sandboxed
applications](https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/5#note_1876550).

While I am very critical of security theater myself, I feel like there is room
for nuance here. These are some of the **ideas** I want to experiment with:

-   Prompt the user when an application tries to access a password to provide some degree of observability
-   Prevent malicious applications from taking memory dumps by using [`PR_SET_DUMPABLE`](https://www.man7.org/linux/man-pages/man2/prctl.2.html)
-   Use a yubikey to store the encryption secret off-device
-   Allow to configure access rules (always allow, always deny, prompt) per application
-   Encrypt the meta data
-   Keep the keyring locked as much as possible without impacting user comfort too much. For example, don't unlock automatically on login.

**I am not claiming that this is or ever will be more secure than
gnome-keyring.** The gnome-keyring developers are much more experienced with
this stuff than I am. For example, they have put a lot of effort into
preventing secrets from being swapped to disk. That is not something I am even
considering (partially because I rely on full disk encryption).

## Deviations from the dbus specification

While this project aims to be a drop-in replacement for gnome-keyring, some
features of the `org.freedesktop.Secrets` specification have been simplified:

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
