# Stock Activation OS Syscall Gap

This file is not a procedure. It does not authorize mount, systemctl,
provisioning, closure copy, or activation. No command in this file may be
executed to change the host. Activation remains unauthorized until the sha256
of this file itself has been independently reviewed and pinned elsewhere.
This file does not embed its own hash.

Bindings:

- BASE_SHA256 70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9
- ADDENDUM_SHA256 ba9791ac89a15b2820f8d9cd8686ef67ef903833bab2eaf62c592d75bbab9fd
- CODE_BASE e0726065eb5d810d87dbea262319c9cd365bbdd1

## G1 CLOSURE_OBJECTS owner placeholder

Addendum 2.4 steps 4 and 6 plus 2.6 do not name the kernel objects, symlink /
hardlink policy, tree fsync order, or non-git equality proof required to
enumerate and freeze the closure. Status: C1 UNEXECUTED. Owner placeholder:
the exact object list, link policy, fsync order, and equality check are still
missing. `export_closure` in the fixture adapter stays at
CLOSURE_ENUMERATION_UNSPECIFIED with zero copies and no git invocation.

## G2 MOUNT_SYSCALL owner placeholder

Addendum 2.2 allows erofs, squashfs, or ro bind but gives no mount(2) flags
or backing-writability syscall. Status: C2 UNEXECUTED. Owner placeholder:
the mount(2) argv, flag set, and backing-store writability proof are still
missing. Code must not choose one. The fixture adapter provides no mount
path and `provisioning_recipe.mount_argv` remains None.

## G3 SYSTEMCTL_ARGV owner placeholder

Addendum 2.5 and 2.12 name the operations and properties but not absolute
argv or sanitized env. Status: C3 UNEXECUTED. Owner placeholder: the exact
absolute argv vectors and the sanitized environment mapping are still
missing. `provisioning_recipe.systemctl_argv` remains None. The subprocess
boundary refuses systemctl, mount, umount, sudo, git, and hermes basenames
before any spawn.

## G4 PROVISION_ARGV owner placeholder

Journal dir mode 0700 uid 0 is named; the root command argv is not, and this
slice must not create it. Status: C4 UNEXECUTED. Owner placeholder: the
privileged provisioning command argv, parent dir handling, and idempotency
proof are still missing. `provisioning_recipe` remains INERT with
`executed: False`.

## Fixture adapter scope

The fixture adapter in `scripts/stock_activation/os_adapter.py` is not an
implementation of G1-G4. It provides only a hermetic fixture filesystem
(write_temp, file_fsync, dir_fsync, rename, read, file_info,
publish_sequence) and a subprocess boundary (refuse-by-default,
fixture-root-only transport). It performs no closure enumeration, no mount,
no systemctl, and no provisioning.

What blocks G1-G4 is the missing syscall fields above, not the absence of
an activation switch. Adding a switch without the named argv, flags, object
list, link policy, fsync order, and equality proofs would not close any gap.
