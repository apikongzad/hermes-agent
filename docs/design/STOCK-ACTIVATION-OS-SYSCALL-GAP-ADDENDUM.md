# Stock Activation OS Syscall Gap Addendum

This file is not a procedure. It is a design record in plain prose and
tables. No sentence in this file may be executed to change the host.
It authorizes no mount, no umount, no losetup attach, no systemctl
stop, start, restart, enable, or daemon-reload, no package install, no
provisioning, no closure copy, and no activation. There is no execution
root named in this file. Every acceptance row in this file stays
UNEXECUTED.

This file does not embed its own sha256. A later GO on this file's own
sha256 would authorize only a hermetic implementation slice. It would
not authorize provisioning, install, restart, daemon-reload, merge, or
live activation. That later slice would still require independent review
of its own bytes.

## 1. Bindings

| Name | Value |
|---|---|
| BASE_SHA256 | 70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9 |
| ADDENDUM_SHA256 | ba9791ac89a15b2820f8d9cd8686ef67ef903833bab2eaf62c592da75bbab9fd |
| GAP_SHA256 | 246567b90ba0d22bc2d45a122da23813c85a0cbd709aead116aabc04f870e3d7 |
| CODE_BASE | 5666a25571a6f8241558673555a0000f9193eae2 |

The base file is `docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md`.
The accepted addendum is
`docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR-ADDENDUM.md`.
The gap file is `docs/design/STOCK-ACTIVATION-OS-SYSCALL-GAP.md`.

## 2. Scope

This file controls G1 through G4 where the gap file still says owner
placeholder. It does not replace the accepted addendum. It supplies the
fields that addendum sections 2.2, 2.4 steps 4 and 6, 2.5, 2.6, and 2.12
left unnamed. Where this file names an argv or a path, that name is the
missing field.

This file does not reopen order, health, EnvironmentFile, or the 0700
journal directory. Those subjects remain closed by the accepted
addendum.

The token INTERPRETER_PREFIX names the decoded UTF-8 string of the
authoritative hex recorded in the task, namely the directory
`/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64`. That
directory was confirmed to exist with os.path.isdir. No other tools
directory name is invented. Every path below that begins with that
prefix refers to that same directory.

## 3. Host evidence observed 2026-10-28T04:01:58Z, read-only

The following paragraphs record read-only observations. They are
evidence, not a claim that a snapshot exists. Nothing in this section
was created, mounted, started, or changed for this authoring.

The host reports Linux 7.0.0-1013-oracle aarch64. CONFIG_SQUASHFS=y.
CONFIG_BLK_DEV_LOOP=y. The name squashfs is present in
/proc/filesystems. CONFIG_EROFS_FS=m and the name erofs is not present
in /proc/filesystems.

The following paths are present and root-owned: /usr/bin/mount
(setuid, util-linux 2.39.3), /usr/bin/umount, /usr/bin/findmnt,
/usr/sbin/losetup, /usr/bin/mksquashfs 4.6.1, /usr/bin/unsquashfs,
/usr/bin/systemctl (systemd 255), /usr/bin/git, /usr/bin/tar,
/usr/bin/rsync (with --fsync), /usr/bin/install, /usr/bin/sleep,
/usr/bin/env, /usr/bin/sha256sum, /usr/bin/python3.12 (a root-owned
binary; /usr/bin/python3 is a symlink to it).

The following names are absent: mkfs.erofs, fsck.erofs, dump.erofs,
mkfs.squashfs. They were not installed. erofs is not the mechanism.

Sudo without a password is available to uid 1001. That availability is
recorded here and is not permission to use it from this document.

The live gateway pid 583405 and the live dashboard pid 583247 are alive,
uid 1001, PPid 1. The ExecStart argv is the generation venv python plus
the worktree script. The resolved exe is
INTERPRETER_PREFIX/bin/python3.14. The recorded gateway cmdline is the
generation venv python path
`/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3`
followed by the worktree script path
`/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025/hermes_cli/main.py`
followed by `gateway run`. The dashboard cmdline adds `dashboard --port
9119 --host 127.0.0.1 --no-open --skip-build`. WorkingDirectory stays
/home/ubuntu/.hermes for the gateway and /home/ubuntu for the
dashboard. User is ubuntu and Group is ubuntu. Restart is always and
RestartUSec is 5s. NRestarts is 0. MainPID values are the two pids
above. There are no BindPaths, BindReadOnlyPaths, RootDirectory, or
RootImage entries.

The live worktree path
`/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025`
does not exist. Commit 1d9a377fa00ce0e663e274e16b63c75e36233b9e exists
as a commit object in /home/ubuntu/.hermes/hermes-agent (mode 0775, uid
1001). It is not in the candidate repo.

The candidate directory
`/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`
exists, uid 1001, mode 0700, with git HEAD
daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06. It is a copy input, not an
execution root.

Generation venvs exist at
`/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c`
(mode 0755, uid 1001) and
`/home/ubuntu/.hermes/runtime/cutover-generations/gen-daec3cd4c6d3`
(mode 0700, uid 1001). Each has exactly three escaping symlinks,
namely bin/python, bin/python3, and bin/python3.14, each resolving to
INTERPRETER_PREFIX/bin/python3.14. The pyvenv.cfg of both records
version_info 3.14.9, include-system-site-packages=false,
relocatable=true, and home INTERPRETER_PREFIX/bin.

The live mapped native extensions are not the generation venv copies.
The maps of pid 583405 and pid 583247 name
`/home/ubuntu/.hermes/installs/fb097378e0b9d4af/environments/3db97cb527a04c959b19c09c3c48bf7c/venv`.
The rpds extension inode there differs from the generation venv inode.
That installs venv is a known-good copy input. Its .leases sibling is
not. That installs venv is not placed in the candidate image.

The interpreter readelf records RPATH $ORIGIN/../lib and NEEDED sonames
libpthread.so.0, libdl.so.2, libutil.so.1, libm.so.6, librt.so.1,
libgcc_s.so.1, libc.so.6, and ld-linux-aarch64.so.1. Those sonames
resolve under /usr/lib/aarch64-linux-gnu and /lib/aarch64-linux-gnu,
which are root-owned host ABI. They are not copied. INTERPRETER_PREFIX
has zero absolute symlinks and 1048 relative symlinks.
libpython3.14.so.1.0 is inside the prefix.

/var/lib is mode 0755, uid 0, gid 0.
/var/lib/hermes-stock-activation does not exist. /run is mode 0755, uid
0. /run/hermes-stock-activation does not exist. They were not created
in this task.

The zz-runtime drop-ins were hashed read-only and match the accepted
addendum: gateway hash
2a495ff333ffdc6b0b61aeab46718ad135e1bd107754b634b82c0445d68cc9eb,
size 74, mode 0600, uid 0; dashboard hash
aa6d8c52fae720306ded7c9b4b037b33efa48026837484a3b487d9f4a647ffed,
size 124, mode 0600, uid 0. The gateway zzz-candidate.conf hash is
cea239fa7125e562b490bfbad527543a77ad90b364adf5c6049e6eb41ae18103.
The dashboard zzz-candidate.conf hash is
62d740cb06ed650fc8d40209410ad32522e14cdac5d8ff961581062d6a513bab.
The gateway ExecStop and ExecStopPost still name
/home/ubuntu/.hermes/hermes-agent/venv/bin/python. The dashboard show
omitted ExecStop and ExecStopPost, which are treated as unset. The
gateway show omitted EnvironmentFiles. The dashboard EnvironmentFiles
names /home/ubuntu/.hermes/.env. That file was not opened. No
EnvironmentFile is added by this file.

The mount constants are MS_RDONLY=1, MS_NOSUID=2, MS_NODEV=4,
MS_NOEXEC=8, and MS_NOSYMFOLLOW=256. The mount flag word in this design
is 7. MS_NOEXEC is not set. MS_NOSYMFOLLOW is not set. chmod is not
immutability.

## 4. G1 closure objects

G1 names the exact copy inputs. None of them is an execution root.

### 4.1 Known-good image inputs

| # | Input | Recorded name |
|---|---|---|
| 1 | Source | Hermetic git archive of commit 1d9a377fa00ce0e663e274e16b63c75e36233b9e from /home/ubuntu/.hermes/hermes-agent. The missing worktree path is not an input. The gen-1d9a377fa00c directory is not the source root. |
| 2 | Launcher venv | /home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv |
| 3 | Mapped dependency venv | /home/ubuntu/.hermes/installs/fb097378e0b9d4af/environments/3db97cb527a04c959b19c09c3c48bf7c/venv |
| 4 | Interpreter prefix | INTERPRETER_PREFIX |

### 4.2 Candidate image inputs

| # | Input | Recorded name |
|---|---|---|
| 1 | Source | Hermetic git archive of commit daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06 from /home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06. Untracked files are not copied. .git is not copied. |
| 2 | Launcher venv | /home/ubuntu/.hermes/runtime/cutover-generations/gen-daec3cd4c6d3/venv |
| 3 | Interpreter prefix | The same INTERPRETER_PREFIX. The live installs environment is not included. |

### 4.3 Snapshot-internal layout, both images

| Path in image | Origin |
|---|---|
| source/ | From the archive |
| venv/ | From the generation venv |
| interpreter/ | From INTERPRETER_PREFIX |

Known-good only also carries deps/ from the mapped installs venv.

### 4.4 Denylist

The image is refused if the staged tree violates the denylist, rather
than silently omitting a required file. The denied names are: a path
component named .git; a path component named .env; the filename
.envrc; a path component named __pycache__; the suffix .pyc; a path
component named .leases; the filenames state.db, state.db-wal, and
state.db-shm; and any fifo, socket, or device node. Library modules
whose names contain the substring credential are not excluded.
.env.example may be copied. User data, logs, and /home/ubuntu/.hermes/.env
are not inputs.

### 4.5 Symlink and hardlink policy

Relative symlinks whose resolved target stays inside the staged tree
are preserved. Every other symlink is refused except the three venv
python names. The names venv/bin/python, venv/bin/python3, and
venv/bin/python3.14 are replaced with relative symlinks to
../../interpreter/bin/python3.14. In deps/bin the same relative target
is used.

The pyvenv.cfg home field, in both venv and the known-good deps, is
rewritten to the execution mount path plus /interpreter/bin. The
known-good mount path is /run/hermes-stock-activation/known-good-snap.
The candidate mount path is
/run/hermes-stock-activation/candidate-snap. The staging path is not
written into pyvenv.cfg.

Editable-finder absolute paths are rewritten. The known-good finder
currently names
/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025;
that prefix is rewritten to
/run/hermes-stock-activation/known-good-snap/source. The candidate
finder has 113 paths under
/home/ubuntu/.hermes/runtime/stock-candidates; that candidate-root
prefix is rewritten to
/run/hermes-stock-activation/candidate-snap/source. Any remaining
absolute path refuses the image.

No hardlinks are created in the image. The mksquashfs no-hardlinks
option stores duplicates. Creating a new hardlink on the mounted
filesystem must fail with EROFS. That denial is a property of the
mount, not of the image flag.

### 4.6 fsync order, both copies, restating addendum 2.6 for these objects

Each regular file is written to a temp name in the same root-owned
directory with O_CREAT, O_EXCL, and O_NOFOLLOW, then the file is
fsynced, then renamed, then the containing directory is fsynced.

Directories are fsynced after their children, bottom-up, including the
staging root.

The squashfs image is written to a temp name in the backing directory,
then the file is fsynced, then renamed to the final image name, then
the backing directory is fsynced.

An OSError from either fsync is durable-state-unknown. There is no
mount and no start on that outcome. If rename succeeded and directory
fsync failed, the state is indeterminate durable-state-unknown, not
success and not rollback-clean.

Host NEEDED libraries are not copied and are not fsynced by this
transaction.

### 4.7 Equality proof, external and unsigned

After staging and rewrites, root computes a canonical manifest of
sorted relative paths with type, mode, sha256 of regular-file bytes,
and relative symlink target. The sha256 of that manifest is the closure
digest.

That digest is stored at
/var/lib/hermes-stock-activation/digest-known-good or
/var/lib/hermes-stock-activation/digest-candidate, mode 0400, uid 0,
gid 0, outside the image and outside every uid-1001 tree. The record
says signed=false. It is not a signature.

The same record also stores the sha256 of the squashfs file.

Before mount, the image is extracted with unsquashfs into a second
private root-owned directory and the manifest is recomputed. Mismatch
refuses mount. The digest is not trusted because the candidate printed
it.

Two archives of the same SHA must have equal sha256 before extract.
Mismatch refuses. The source repos are uid 1001; the image, not the
repo, is the execution boundary.

The symbol export_closure in the fixture adapter remains
CLOSURE_ENUMERATION_UNSPECIFIED with zero copies. This document does
not change that code.

## 5. G2 mount syscall

The only mechanism is squashfs. erofs is blocked because mkfs.erofs is
absent and erofs is not registered in /proc/filesystems. It is not
installed. An ext4 loop image is rejected because a second mount can be
read-write and would fail the hardlink denial. A read-only bind of a
uid-1001 tree is rejected because the backing stays writable. chmod is
not immutability.

### 5.1 Image paths and mountpoints

The image paths carry mode 0400, uid 0, gid 0, and are not mountpoints:

| Image | Path |
|---|---|
| Known-good | /var/lib/hermes-stock-activation/backing/known-good.squashfs |
| Candidate | /var/lib/hermes-stock-activation/backing/candidate.squashfs |

The execution mountpoints sit outside the 0700 journal directory so uid
1001 can traverse them without weakening that directory:

| Mount | Path |
|---|---|
| Known-good | /run/hermes-stock-activation/known-good-snap |
| Candidate | /run/hermes-stock-activation/candidate-snap |

/run is mode 0755, uid 0. The mountpoint parent
/run/hermes-stock-activation is mode 0755, uid 0, gid 0, and is not a
uid-1001 directory. The snapshot constants under backing/ in states.py
are not the execution paths. That file is not edited in this task.

### 5.2 mksquashfs argv

The recorded mksquashfs argv applies after the staged tree is fsynced.
Output goes to a temp name that must not already exist. The recorded
vector is:

`/usr/bin/mksquashfs <staged-tree> <image-temp> -comp xz -b 131072
-reproducible -mkfs-time 0 -all-root -no-xattrs -no-hardlinks
-no-exports -no-recovery -no-progress -noappend`

This is followed by file fsync, rename to the final image name, and
directory fsync.

### 5.3 Loop and mount argv

The loop index is observed, not a constant. The name /dev/loop0 is not
picked because it is in use. The recorded loop vector is:

`/usr/sbin/losetup --find --show --read-only --nooverlap -- <final-image>`

The printed device is required, then losetup must show that device as
read-only with that image as BACK-FILE. If the output is empty, not
read-only, or names a different back-file, there is no mount.

The recorded mount vector is:

`/usr/bin/mount -n -t squashfs -o ro,nosuid,nodev <loopdev> <mountpoint>`

That vector is the mount(2) request: the source is the read-only loop
device, the filesystem type is squashfs, the flags are
MS_RDONLY OR MS_NOSUID OR MS_NODEV which equals 7, and the data
argument is empty. The vector does not pass rw, noexec, remount, or
bind.

After mount, the recorded check vector is:

`/usr/bin/findmnt -n -o FSTYPE,OPTIONS,SOURCE,TARGET --target <mountpoint>`

It must show squashfs, ro, and that loop device. A later remount with
rw must fail. A second mount of the same image is also squashfs
read-only. Writes, renames, and links by uid 1001 on either mount must
return EROFS. Those probes are UNEXECUTED. They are not run now.

## 6. G3 systemctl argv

Every systemctl argv in this section is prefixed by the exact sanitized
launcher and by nothing else:

`/usr/bin/sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin
LANG=C LC_ALL=C SYSTEMD_PAGER= SYSTEMD_COLORS=0`

There is no PYTHONPATH, no credential variable, and no user
environment. The name systemctl restart is not a binding and is not an
argv in this file. It is not used.

The unit names are exactly hermes-gateway.service and
hermes-dashboard.service.

### 6.1 Fence, before any unit publication, unit-byte restore, or start, including interruption recovery

| Step | Recorded argv or check |
|---|---|
| 1 | `/usr/bin/systemctl stop hermes-gateway.service hermes-dashboard.service`, under the launcher prefix |
| 2 | `/usr/bin/systemctl show -p Id -p ActiveState -p SubState -p MainPID -p NRestarts -- hermes-gateway.service hermes-dashboard.service`, under the launcher prefix. Id must be exact, ActiveState must be inactive, MainPID must be 0. NRestarts is recorded. |
| 3 | `/usr/bin/sleep 5`, under the launcher prefix. This wait is the RestartUSec 5s fence. It is not a restart and it does not check binding. |
| 4 | Repeat the same show. Both units remain inactive, MainPID 0, NRestarts unchanged from step 2. |

If either unit is active or NRestarts increases, there is no
publication, no restore, and no start.

### 6.2 Publication

Publication remains only in-place replacement of the two
zzz-candidate.conf files, with file and directory fsync. The
replacement text uses the empty-assignment reset form for ExecStart,
ExecStop, and ExecStopPost. No second drop-in is added. No other
drop-in is edited. No EnvironmentFile is added. The v0.21.7 stop hooks
are not added. If post-reload show still names
/home/ubuntu/.hermes/hermes-agent/venv, the activation is blocked.

### 6.3 After publication and fsync, and only while the fence still holds

| Step | Recorded argv or check |
|---|---|
| 5 | `/usr/bin/systemctl daemon-reload`, under the launcher prefix |
| 6 | `/usr/bin/systemctl show -p Id -p ActiveState -p SubState -p MainPID -p NRestarts -p ExecStart -p ExecStop -p ExecStopPost -p EnvironmentFiles -p FragmentPath -p DropInPaths -- hermes-gateway.service hermes-dashboard.service`, under the launcher prefix. Both units must still be inactive with MainPID 0. ExecStart must be the snapshot argv below. ExecStop and ExecStopPost must be empty. EnvironmentFiles must not be newly set. If show disagrees with the journal, there is no start. |

### 6.4 Start and readback

| Step | Recorded argv or check |
|---|---|
| 7 | `/usr/bin/systemctl start hermes-gateway.service hermes-dashboard.service`, under the launcher prefix. This is one explicit start, not a restart. |
| 8 | Readback, which is the only binding: the same show, plus /proc/sys/kernel/random/boot_id, /proc/<MainPID>/exe, /proc/<MainPID>/cmdline, /proc/<MainPID>/cgroup, and field 22 of /proc/<MainPID>/stat. Mismatch or unreadable identity is failure. No second start and no restart is issued while that identity is ambiguous. |

### 6.5 Snapshot ExecStart argv, inside the mounted image

| Unit | Recorded ExecStart |
|---|---|
| Known-good gateway | /run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I /run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py gateway run |
| Known-good dashboard | /run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I /run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build |
| Candidate gateway | /run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I /run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py gateway run |
| Candidate dashboard | /run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I /run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build |

WorkingDirectory stays the accepted user-data directories. There is no
worktree path, no gen-1d9a377fa00c path, and no PYTHONPATH. The python
-I import proof remains UNEXECUTED. If it fails, activation is blocked.

## 7. G4 provision argv

G4 uses the same sudo env -i prefix as G3, with GIT_CONFIG_GLOBAL,
GIT_CONFIG_SYSTEM, and GIT_CONFIG_NOSYSTEM entries added on git
commands. The recorded git environment is GIT_CONFIG_GLOBAL=/dev/null,
GIT_CONFIG_SYSTEM=/dev/null, and GIT_CONFIG_NOSYSTEM=1.

### 7.1 Layout, all uid 0 gid 0

| Path | Mode | Note |
|---|---|---|
| /var/lib/hermes-stock-activation | 0700 | Journal file and recovery record live here. This directory is not the execution mount. |
| /var/lib/hermes-stock-activation/backing | 0700 | Images and private staging live here. |
| /var/lib/hermes-stock-activation/backing/staging/<16-byte-urandom-hex> | 0700 | Private staging. The nonce comes from /dev/urandom. A predictable name is not used. |
| /var/lib/hermes-stock-activation/journal | 0600 | Created only by a later authorized slice. |
| /var/lib/hermes-stock-activation/recovery | 0500 | Not a shell script, not /opt, not cutover_*.py, and not a uid-1001 path. This document does not install its bytes. |
| /run/hermes-stock-activation | 0755 | Parent of the two mountpoints. |

The external operator runs the argv in this file and exits. There is no
recovery daemon and no systemd unit for recovery.

### 7.2 Idempotent create

Each path is statted first. If the path is absent and its parent is not
a symlink, it is created. If it exists, it must show uid 0, gid 0, the
mode in the table above, and not a symlink; then nothing is done. If it
exists with any other owner, mode, or type, the run is refused. A
foreign directory is not chmodded into compliance. /var/lib is not
chmodded.

The recorded create vectors, used only when the path is absent, are:

`/usr/bin/install -d -o 0 -g 0 -m 0700 /var/lib/hermes-stock-activation`

`/usr/bin/install -d -o 0 -g 0 -m 0700 /var/lib/hermes-stock-activation/backing`

`/usr/bin/install -d -o 0 -g 0 -m 0700 /var/lib/hermes-stock-activation/backing/staging/<nonce>`

`/usr/bin/install -d -o 0 -g 0 -m 0755 /run/hermes-stock-activation`

`/usr/bin/install -d -o 0 -g 0 -m 0755 /run/hermes-stock-activation/known-good-snap`

`/usr/bin/install -d -o 0 -g 0 -m 0755 /run/hermes-stock-activation/candidate-snap`

A second stat after a matching directory must show the same device,
inode, owner, and mode. That is the idempotency proof. The install
vector is not rerun against a matching directory.

### 7.3 Archive argv

The output path must not exist. The recorded archive vector is:

`/usr/bin/git -C <repo> -c core.hooksPath=/dev/null -c core.fsmonitor=false archive --format=tar --output=<staging>/<name>.tar <sha>`

It is run twice to two temp names. Both outputs are checksummed with
sha256sum. Equal hashes are required before extract. Then:

`/usr/bin/tar -C <staging>/source --no-same-owner --no-same-permissions -xf <staging>/<name>.tar`

Then the fsync walker below is applied.

### 7.4 Directory copy of a venv or the interpreter prefix

The recorded copy vector is:

`/usr/bin/rsync -a --fsync --numeric-ids --exclude=.git --exclude=.env --exclude=.envrc --exclude=__pycache__ --exclude=*.pyc --exclude=.leases -- <src>/ <dst>/`

Then the three python symlinks are rewritten with the recorded link
vectors:

`/usr/bin/ln -sfn ../../interpreter/bin/python3.14 <dst>/bin/python`

and the same target for python3 and python3.14. Then pyvenv.cfg and the
editable finder are rewritten with /usr/bin/python3.12 -I, writing
through a temp name with file fsync, rename, and directory fsync. Then
the directory fsync walker is run. The recorded walker vector is:

`/usr/bin/python3.12 -I -c '<program>' <root>`

The program walks with followlinks disabled, opens each regular file
with O_RDONLY and O_NOFOLLOW, fsyncs and closes it, opens each real
directory with O_RDONLY, O_DIRECTORY, and O_NOFOLLOW, fsyncs and closes
it, and raises on any OSError or symlink directory. An exception is
durable-state-unknown.

### 7.5 Verify extract

The recorded verify vector is:

`/usr/bin/unsquashfs -no-xattrs -d <private-verify-dir> <image>`

Manifests are compared. Then the mount argv in G2 applies. The verify
directory is not left as an execution root.

The external operator is the recovery launcher. Each argv above is a
separate invocation that exits. A nonzero exit, an fsync error, a hash
mismatch, or an unknown stat is a stop. The operator does not retry by
deleting the journal. The journal does not exist yet and this document
does not create it.

## 8. Fixture adapter

The file scripts/stock_activation/os_adapter.py remains fixture-only.
The field provisioning_recipe stays INERT. The fields mount_argv,
systemctl_argv, and closure_file_set stay null until a later reviewed
implementation. This addendum is the named contract for those fields.
It is not that implementation.

## 9. Supersession table for the gap file only

The gap file bytes stay unchanged. Each row below states which gap
lines this addendum replaces. Status of each remains UNEXECUTED as a
probe.

| Gap section | Gap placeholder lines replaced | Replacement in this file |
|---|---|---|
| G1 CLOSURE_OBJECTS | Lines naming the owner placeholder for the exact object list, link policy, fsync order, and equality check as missing | Section 4 names the known-good and candidate copy inputs, the snapshot-internal layout, the denylist, the symlink and hardlink policy, the fsync order, and the external unsigned equality proof |
| G2 MOUNT_SYSCALL | Lines naming the owner placeholder for the mount(2) argv, flag set, and backing-store writability proof as missing | Section 5 names squashfs as the only mechanism, the image paths, the execution mountpoints, the mksquashfs argv, the loop and mount argv with flag word 7, and the findmnt plus EROFS checks |
| G3 SYSTEMCTL_ARGV | Lines naming the owner placeholder for the exact absolute argv vectors and the sanitized environment mapping as missing | Section 6 names the sudo env -i launcher prefix, the unit names, the stop plus show plus sleep-5 fence, the publication rule, the daemon-reload plus show checks, and the single start plus readback, with the snapshot ExecStart argv |
| G4 PROVISION_ARGV | Lines naming the owner placeholder for the privileged provisioning command argv, parent directory handling, and idempotency proof as missing | Section 7 names the layout, the stat-before-create rule, the install argv, the archive and rsync argv, the symlink and config rewrites, the fsync walker, and the unsquashfs verify step |

## 10. Acceptance rows

Rows A1 through A13 and B1 through B7 are defined by the base and the
accepted addendum. They remain UNEXECUTED. No row in this file is
passed. The added C rows below are also UNEXECUTED.

| Row | Statement | Status |
|---|---|---|
| A1 | Base acceptance row A1 | UNEXECUTED |
| A2 | Base acceptance row A2 | UNEXECUTED |
| A3 | Base acceptance row A3 | UNEXECUTED |
| A4 | Base acceptance row A4 | UNEXECUTED |
| A5 | Base acceptance row A5 | UNEXECUTED |
| A6 | Base acceptance row A6 | UNEXECUTED |
| A7 | Base acceptance row A7 | UNEXECUTED |
| A8 | Base acceptance row A8 | UNEXECUTED |
| A9 | Base acceptance row A9 | UNEXECUTED |
| A10 | Base acceptance row A10 | UNEXECUTED |
| A11 | Base acceptance row A11 | UNEXECUTED |
| A12 | Base acceptance row A12 | UNEXECUTED |
| A13 | Base acceptance row A13 | UNEXECUTED |
| B1 | Accepted-addendum acceptance row B1 | UNEXECUTED |
| B2 | Accepted-addendum acceptance row B2 | UNEXECUTED |
| B3 | Accepted-addendum acceptance row B3 | UNEXECUTED |
| B4 | Accepted-addendum acceptance row B4 | UNEXECUTED |
| B5 | Accepted-addendum acceptance row B5 | UNEXECUTED |
| B6 | Accepted-addendum acceptance row B6 | UNEXECUTED |
| B7 | Accepted-addendum acceptance row B7 | UNEXECUTED |
| C1 | Closure manifest equals unsquashfs extract and excludes .env | UNEXECUTED |
| C2 | Second squashfs mount denies uid-1001 write, rename, and link with EROFS, and remount with rw fails | UNEXECUTED |
| C3 | Stop, show inactive, sleep 5, show unchanged NRestarts, daemon-reload, start, readback; no systemctl restart | UNEXECUTED |
| C4 | Stat-before-create refuses a foreign directory and does not chmod /var/lib | UNEXECUTED |

## 11. Checklist

| Item | Authorization |
|---|---|
| ACTIVATION | not authorized |
| PROVISIONING | not authorized |
| MOUNT | not authorized |
| SYSTEMCTL | not authorized |
| HERMETIC_IMPLEMENTATION | not authorized by this authoring |
| LIVE_MUTATION | not performed |
