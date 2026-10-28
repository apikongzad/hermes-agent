"""Stock cutover production transaction. Stdlib only. No live effects in worker.

Separate from operator proof (which stays NOT_AUTHORIZED). This package
implements the accepted external root transaction: exact unit bytes,
root-independent journal, fence, health, rollback, recovery supervision.
Worker never executes live systemctl/mount; parent installs reviewed
package under /var/lib/hermes-stock-activation/recovery and runs as root.
"""
