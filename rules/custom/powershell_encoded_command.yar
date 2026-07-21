rule Qilin_Suspicious_PowerShell_EncodedCommand
{
    meta:
        author      = "qilin"
        description = "PowerShell invoked with a base64-encoded command (-enc/-EncodedCommand) alongside flags that hide the window and skip the profile/policy checks. This exact flag combination is the standard living-off-the-land pattern for staged droppers and macro payloads, and is uncommon in legitimate scripts/shortcuts."

    strings:
        $encoded = /-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b/ nocase ascii wide
        $hidden  = /-(w|win|wind|windo|window|windowstyle)\s+(h|hi|hid|hidd|hidde|hidden)\b/ nocase ascii wide
        $noprofile = "-noprofile" nocase ascii wide
        $bypass = "-executionpolicy" nocase ascii wide
        $powershell = "powershell" nocase ascii wide

    condition:
        $powershell and $encoded and (1 of ($hidden, $noprofile, $bypass))
}
