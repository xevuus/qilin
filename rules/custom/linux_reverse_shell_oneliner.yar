rule Qilin_Linux_Reverse_Shell_OneLiner
{
    meta:
        author      = "qilin"
        description = "Common copy-pasted Linux reverse-shell one-liners (bash /dev/tcp, nc -e, mkfifo+nc, python socket+dup2). These show up verbatim in webshells, cron persistence, and CTF payloads because operators reuse the same public snippets rather than writing custom shells."

    strings:
        $bash_devtcp = /bash\s+-[ci]{1,2}\s+>&\s*\/dev\/tcp\/[^\s]+\/\d+\s*0(&1)?/ ascii
        $nc_e = /nc(\.traditional)?\s+(-[a-zA-Z]*e[a-zA-Z]*\s+\S+|[^\n]*-e\s+\/bin\/(ba)?sh)/ ascii
        $mkfifo_nc = "mkfifo /tmp/" ascii
        $python_socket = /socket\.socket\([^\)]*\).{0,80}dup2/ ascii
        $perl_socket = "socket(S,PF_INET,SOCK_STREAM" ascii

    condition:
        any of them
}
