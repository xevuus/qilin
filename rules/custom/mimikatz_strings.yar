rule Qilin_Mimikatz_Artifacts
{
    meta:
        author      = "qilin"
        description = "Command/module strings unique to Mimikatz and its common forks (Kiwi, Invoke-Mimikatz). These are hardcoded in the tool's command dispatcher, so they survive even when the rest of the binary is rebuilt or reflectively loaded."

    strings:
        $banner    = "mimikatz #" ascii wide nocase
        $sekurlsa  = "sekurlsa::logonpasswords" ascii wide nocase
        $lsadump   = "lsadump::" ascii wide nocase
        $kerberos  = "kerberos::ptt" ascii wide nocase
        $crypto    = "CredentialKeys" ascii wide
        $gentilkiwi = "gentilkiwi" ascii wide nocase

    condition:
        2 of them
}
