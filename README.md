# 🔒 LinRPE Linux Privilege Escalation - Auto-Exploit (em construção)

Este projeto é um script simples em **Bash** que automatiza a detecção e exploração básica para escalonamento de privilégios no Linux, com base nas técnicas documentadas no [GTFOBins](https://gtfobins.github.io/).

> ⚠️ **Aviso:** Este script está em desenvolvimento e é voltado apenas para **uso educacional e em ambientes controlados (CTF, laboratórios, pentest autorizado)**.

---

## 📌 O que ele faz?

- Procura binários com a flag SUID (`find / -perm -u=s -type f`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins
- Caso exista, executa o exploit automaticamente ou mostra um exemplo de uso

---

## ✅ Binários atualmente suportados

- `bash`
- `aa-exec`
- `ab`
- `agetty`
- `alpine`
- `ar`
- `arj`
- `arp`
- `as`
- `ascii-xfr`
- `ash`
- `aspell`
- `atobm`
- `awk`
- `base32`
- `base64`
- `basenc`
- `basez`
- `bc`
- `bridge`
- `busctl`
- `busybox`
- `bzip2`
- `cabal`
- `capsh`
- `cat`
- `chmod`
- `choom`
- `chown`
- `chroot`
- `clamscan`
- `cmp`
- `column`
- `comm`
- *(outros sendo adicionados...)*

---

## 🛠️ Exemplo de uso

```bash
chmod +x suid_exploit.sh
./suid_exploit.sh
```

---

## 📅 Status

>  **Em construção** — funcionalidades estão sendo adicionadas gradualmente.  
> Contribuições e sugestões são bem-vindas!

---

## 📚 Fontes

- [GTFOBins](https://gtfobins.github.io/)
- Experimentos em ambientes CTF

---

