# goatcli-windows-spawn

This internal GOAT launcher component provides the Windows process-creation
boundary for privacy IPC. It selects an exact-version native package for the
current supported Windows architecture and rejects missing or mismatched native
ABI versions.

The public interface is intentionally limited to spawning the child, receiving
its exit notification, transferring the two launcher descriptors exactly once,
terminating it, and closing retained native resources.
