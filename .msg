fix: terminate host supervisor on stop for clean resume

stop_sandbox was not terminating the host supervisor before stopping
the Apple container, leaving a stale supervisor racing to reconnect
to a dead boundary. start_sandbox's re-spawn would then fail because
the old supervisor was still in the children map.

Now stop_sandbox calls terminate_host_supervisor() before stopping
the container, matching delete_sandbox's behavior. The staging dir
is preserved so start_sandbox can re-spawn from the same auth bundle.
