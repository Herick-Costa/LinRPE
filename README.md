# 🔒 Projeto LinRPE Linux Privilege Escalation - Auto-Exploit (em construção)

Este projeto é um conjunto de scripts simples em **Bash** que automatiza a detecção e exploração básica de **tecnicas clássicas de escalonamento de privilégios** no Linux, usando como base as técnicas documentadas no [GTFOBins](https://gtfobins.github.io/).

---
> ⚠️ **Aviso:** Estes scripts estão em desenvolvimento e são voltados apenas para **uso educacional e em ambientes controlados (CTF, laboratórios, pentest autorizado)**.

---
# LinRPE.sh
## 📌 O que ele faz?

- Junção de todos os scripts - Ainda em testes ⚠️
- Executa a verificação de SUIDs
- Em seguida de Capabilities
- Em seguida sudo -l -n
- E pergunta se quer testar Limited SUIDs
- Caso encontre alguma combinação em algum ponto da execução executa o exploit ou mostra um exemplo

https://github.com/user-attachments/assets/f5951466-75ad-4c34-bfdc-f6cda3077835

---

# SUID.sh
## 📌 O que ele faz?

- Procura binários com a flag SUID (`find / -perm -u=s -type f`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins
- Caso exista, executa o exploit automaticamente ou exibi um exemplo de uso
- Não inclui Limited SUID
  
---

# Capabilities.sh
## 📌 O que ele faz?

- Procura binários com capabilities setadas usando (`getcap -r / 2>/dev/null`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins
- Caso exista, executa o exploit automaticamente ou exibi um exemplo de uso

---

# sudo-l.sh
## 📌 O que ele faz?

- Executa `sudo -l -n` para listar comandos que o usuário pode rodar como root
- Se o sudo -l não exigir senha, analisa a saída em busca de comandos com NOPASSWD
- Para cada comando listado, verifica se há um exploit conhecido (GTFOBins)
- Se houver, executa automaticamente ou mostra um exemplo de uso

<img width="971" height="151" alt="image" src="https://github.com/user-attachments/assets/49c7e936-7a3e-4a96-8ece-fc0287e928b0" />

---

# LimitedSUID.sh
## 📌 O que ele faz?

- Procura binários com a flag SUID (`find / -perm -u=s -type f`)
- Para cada binário encontrado, verifica se existe um exploit conhecido no GTFOBins para Limited SUID
- Caso exista, executa o exploit automaticamente ou exibi um exemplo de uso

---

## 📅 Status

>  **Em construção** — funcionalidades estão sendo adicionadas gradualmente.  
> Contribuições e sugestões são bem-vindas!

---

## 📚 Fontes

- [GTFOBins](https://gtfobins.github.io/)
- Experimentos em ambientes CTF

---

