# 🔒 Projeto LinRPE Linux Privilege Escalation - Auto-Exploit (em construção)

Este projeto é um conjunto de scripts simples em **Bash** que automatiza a detecção e exploração básica de **tecnicas clássicas de escalonamento de privilégios** no Linux, usando como base as técnicas documentadas no [GTFOBins](https://gtfobins.github.io/).

---
> ⚠️ **Aviso:** Estes scripts estão em desenvolvimento e são voltados apenas para **uso educacional e em ambientes controlados (CTF, laboratórios, pentest autorizado)**.

---
# LinRPE.sh
## 📌 O que ele faz?

- Junção de todos os scripts - Ainda em construção ⚠️

---

# SUID.sh
## 📌 O que ele faz?

- Procura binários com a flag SUID (`find / -perm -u=s -type f`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins
- Caso exista, executa o exploit automaticamente ou exibi um exemplo de uso

---

# Capabilities.sh
## 📌 O que ele faz?

- Procura binários com capabilities setadas usando (`getcap -r / 2>/dev/null`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins
- Caso exista, executa o exploit automaticamente ou exibi um exemplo de uso

---

# sudo-l.sh
## 📌 O que ele faz?

- Ainda em construção ⚠️

---

## 📅 Status

>  **Em construção** — funcionalidades estão sendo adicionadas gradualmente.  
> Contribuições e sugestões são bem-vindas!

---

## 📚 Fontes

- [GTFOBins](https://gtfobins.github.io/)
- Experimentos em ambientes CTF

---

