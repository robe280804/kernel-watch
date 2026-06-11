# Regole di detection

Il detector (`internal/detector/detector.go`) esegue sei regole su ogni evento
**proveniente da un container** (gli eventi host sono ignorati). Le regole girano
**nell'ordine sottostante** e vince la **prima che matcha** — un solo alert per evento.

- le **regole exec** matchano sul nome processo esatto (`comm`, in minuscolo) di un
  evento `execve`.
- le **regole file** matchano su un **prefisso di percorso** del filename di un evento
  `openat`.

Ogni alert porta una severità e una tecnica MITRE ATT&CK (TTP) + tattica.

---

## 1. Shell nel container — `ruleShellInContainer`

- **Trigger:** un `execve` il cui nome processo è esattamente uno tra
  `sh`, `bash`, `zsh`, `fish`, `dash`, `ash`.
- **Severità:** High · **MITRE:** T1059 (Execution).
- **Perché:** i container di produzione dovrebbero raramente, se non mai, avviare una
  shell interattiva. Una shell spesso indica un'intrusione hands-on-keyboard o un
  `docker exec` in un workload che non dovrebbe averne bisogno.

## 2. Tool di privilege escalation — `rulePrivilegedProcessInContainer`

- **Trigger:** un `execve` chiamato `sudo`, `su`, `nsenter`, `unshare`, `chroot`,
  `capsh`, `setuid`, `newgrp`.
- **Severità:** High · **MITRE:** T1548 (Privilege Escalation).
- **Perché:** questi tool servono a ottenere privilegi più alti o a rompere
  l'isolamento dei namespace; `nsenter`/`unshare` in particolare sono primitive di
  container escape.

## 3. Accesso a file sensibili — `ruleSensitiveFileAccess`

- **Trigger:** un `openat` il cui percorso inizia con uno tra
  `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh`,
  `/var/run/docker.sock`, `/.dockerenv`, `/proc/sysrq-trigger`, `/proc/kcore`.
- **Severità:** Medium (T1005, Collection) — **elevata a Critical (T1611, Privilege
  Escalation)** quando il percorso è esattamente `/var/run/docker.sock`.
- **Perché:** questi file rivelano credenziali, stato dell'host o — nel caso del socket
  Docker — una via diretta al takeover completo dell'host dall'interno di un container.

## 4. Tool di ricognizione di rete — `ruleUnexpectedNetworkTool`

- **Trigger:** un `execve` chiamato `nmap`, `masscan`, `netcat`, `nc`, `ncat`,
  `tcpdump`, `wireshark`, `tshark`, `curl`, `wget`.
- **Severità:** Medium, **High** per `nmap`/`masscan` · **MITRE:** T1046 (Discovery).
- **Perché:** scanner/sniffer indicano ricognizione per movimento laterale;
  `curl`/`wget` compaiono spesso nelle catene di download post-exploitation.

## 5. Package manager in un container in esecuzione — `rulePackageManagerInContainer`

- **Trigger:** un `execve` chiamato `apt`, `apt-get`, `dpkg`, `yum`, `dnf`, `rpm`,
  `apk`, `pip`, `pip3`, `npm`, `yarn`, `gem`.
- **Severità:** Medium · **MITRE:** T1072 (Execution).
- **Perché:** installare pacchetti a runtime è anomalo per immagini di produzione
  immutabili e spesso significa che un attaccante sta portando dentro strumenti.

## 6. Accesso a file di credenziali — `ruleCredentialFileAccess`

- **Trigger:** un `openat` il cui percorso inizia con uno tra
  `/.env`, `/.aws/credentials`, `/.gcloud/credentials`, `/run/secrets`,
  `/.kube/config`.
- **Severità:** High · **MITRE:** T1552 (Credential Access).
- **Perché:** classici bersagli per il furto di credenziali — chiavi cloud, config
  Kubernetes, secret Docker, file `.env` delle applicazioni.

---

## Soglia di severità

Se un alert venga effettivamente consegnato dipende anche da `KW_ALERT_MIN_SEVERITY`
(vedi [configuration.md](configuration.md)). Con il default `medium`, gli alert `low`
sarebbero soppressi — anche se nessuna delle regole attuali emette `low`.

## Limitazioni note del matching

- **Match per nome esatto:** un binario rinominato (es. `bash` copiato in `xyz`) elude
  le regole exec. L'ispezione degli argomenti non è ancora implementata.
- **Match per prefisso sul percorso nel container:** il filename è ciò che il container
  ha passato alla syscall, che può essere relativo o differire dalla vista dell'host;
  restringi i percorsi con cautela.
- **Solo prima corrispondenza:** un evento che soddisfa due regole segnala solo la
  prima nell'ordine del detector. Questo deduplica gli alert ma significa che l'ordine
  delle regole conta.

## Aggiungere una regola

Implementa un `func(collector.Event) *alerter.Alert`, restituendo `nil` quando non si
applica, e registralo nello slice di `New()`. Vedi [development.md](development.md) per
un esempio completo.
