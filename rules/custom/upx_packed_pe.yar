rule Qilin_UPX_Packed_PE
{
    meta:
        author      = "qilin"
        description = "Windows PE that has been packed with UPX. Packing itself isn't malicious, but it's a common first step malware takes to defeat static AV signatures, so it's a useful triage signal."
        reference    = "https://upx.github.io/"

    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $marker = "UPX!" ascii

    condition:
        $mz at 0
        and uint32(uint32(0x3C)) == 0x00004550
        and $upx0 and $upx1 and $marker
}
