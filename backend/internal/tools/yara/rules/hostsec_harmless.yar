// Reviewed HostSec lab rule. Detects only the harmless test marker.
rule hostsec_harmless
{
    strings:
        $a = "harmless_marker"
    condition:
        $a
}
