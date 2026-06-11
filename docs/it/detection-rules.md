# Regole di detection

Il detector (`internal/detector/`) è **consapevole del contesto**: valuta ogni
evento di un **container** (gli eventi dell'host vengono ignorati) non solo in
base al binario coinvolto, ma in base a **chi lo ha avviato (la genealogia dei
processi)** e **con quali argomenti (argv)**. È questo che distingue gli attacchi
reali dalle normali operazioni: lo stesso `sh` o `curl` è benigno se avviato da
`cron` ed è un probabile web-shell se avviato da `nginx`.

Le regole sono unità dichiarative (`internal/detector/rules.go`) costruite da
**liste** riutilizzabili (`lists.go`). Il motore (`detector.go`) esegue **tutte**
le regole, applica le **eccezioni** dell'operatore e deduplica per
`(regola, container, pid)` entro una breve finestra. Ogni alert riporta id della
regola, severità, tecnica/tattica MITRE ATT&CK, tag, il genitore/genealogia e la
riga di comando.

## Arricchimento alla base delle regole

Il collector traccia 8 tracepoint di syscall (execve, openat, connect, clone,
ptrace, init_module, finit_module, bpf). Per gli eventi `execve` (e
`ptrace`/module/`bpf`) dei container monitorati risolve, in userspace (tramite
`/proc`, come la già presente lettura del cgroup — nessun eBPF aggiuntivo):

- **Genealogia** — la catena dei nomi dei processi genitori (`/proc/<pid>/stat`
  → `/proc/<ppid>/comm`), fino a `KW_ANCESTRY_DEPTH` (default 5), dal genitore
  immediato in poi.
- **Riga di comando** — `/proc/<pid>/cmdline` (l'argv eseguito).
- **Nome/immagine del container** — risolti dal socket Docker, così alert e
  filtri `KW_CONTAINER_*` usano i nomi reali invece degli ID brevi.

## Classificazione della genealogia

Ogni catena di genealogia è classificata tramite due liste (sovrascrivibili da
configurazione):

- **Trusted** (`KW_TRUSTED_PARENTS` + integrati: `init`, `systemd`, `cron`,
  `containerd-shim`, `runc`, `tini`, `dumb-init`, `s6-*`, `supervisord`, …) —
  supervisori/scheduler/entrypoint benigni.
- **Network-facing** (`KW_NETWORK_PARENTS` + integrati: `nginx`, `apache2`,
  `httpd`, `php-fpm`, `php`, `node`, `python`, `java`, `ruby`, `puma`,
  `gunicorn`, `mysqld`, `postgres`, `redis-server`, …) — runtime di servizi
  esposti in rete. In caso di entrambi nella catena, **prevale network-facing**.

---

## Regole

| Id regola | Trigger | Comportamento per genealogia | Severità | MITRE |
|-----------|---------|------------------------------|----------|-------|
| `kernel_module_load` | `init_module`/`finit_module` da un container | n/d | **Critical** | T1547.006 Persistence |
| `bpf_prog_load` | `bpf(BPF_PROG_LOAD)` da un container | n/d | High | T1562.001 Defense Evasion |
| `process_injection` | `ptrace` con POKETEXT/POKEDATA/POKEUSR/SETREGS/ATTACH/SEIZE | n/d | High | T1055.008 Privilege Escalation |
| `persistence` | open in **scrittura** di percorsi cron/systemd/`ld.so.preload`/`authorized_keys`/`sudoers.d`/profile | n/d | High (Critical per `ld.so.preload`) | T1543 Persistence |
| `reverse_shell` | cmdline di `execve` con firma di reverse shell (`/dev/tcp/`, `/dev/udp/`, `nc -e`, `ncat -e`, `pty.spawn`, `socket.socket`, o `curl/wget … \| sh`) | scatta sempre (mai benigna) | **Critical** | T1059 Execution |
| `shell_in_container` | `execve` di `sh`/`bash`/`zsh`/`fish`/`dash`/`ash`/`ksh`/`tcsh` | network → **Critical** (RCE/web-shell); trusted → **soppressa**; sconosciuta → High | High→Critical | T1059 Execution |
| `privilege_escalation` | `execve` di `sudo`/`su`/`nsenter`/`unshare`/`chroot`/`capsh`/`setuid`/`newgrp` | network → **Critical**; trusted → soppressa; sconosciuta → High | High→Critical | T1548 Privilege Escalation |
| `network_tool` | `execve` di `nmap`/`masscan`/`nc`/`ncat`/`netcat`/`socat`/`curl`/`wget`/`tcpdump`/… | network → **High**; trusted → **soppressa**; sconosciuta → Medium (High per `nmap`/`masscan`) | Medium→High | T1046 Discovery |
| `container_drift` | `execve` di un binario sotto `/tmp`, `/dev/shm`, `/var/tmp`, `/run` | n/d | High | T1036 Defense Evasion |
| `package_manager` | `execve` di `apt`/`apt-get`/`dpkg`/`yum`/`dnf`/`apk`/`pip`/`npm`/… | network → **High**; trusted → soppressa; sconosciuta → Medium | Medium→High | T1072 Execution |
| `sensitive_file` | prefisso di percorso `openat` tra `/etc/shadow`, `/root/.ssh`, `/var/run/docker.sock`, … | n/d | Medium (Critical per docker.sock → T1611) | T1005 Collection |
| `credential_file` | prefisso di percorso `openat` tra `/.env`, `/.aws/credentials`, `/run/secrets`, `/.kube/config`, … | n/d | High | T1552 Credential Access |

Il cambiamento decisivo: `shell_in_container`, `network_tool`,
`package_manager` e `privilege_escalation` vengono **soppresse** per genealogia
trusted (eliminando il rumore di scheduler/healthcheck/autoheal) ed **elevate**
per genealogia network-facing (intercettando RCE/web-shell reali).

---

## Modalità operative e tuning

- **`KW_MODE`** — `alert` (default) invia gli alert; `monitor` è una modalità
  dry-run che valuta e registra ma non chiama mai webhook/Slack. Usa `monitor`
  per un periodo di rollout/tuning sicuro su un nuovo host.
- **`KW_DETECTION_EXCEPTIONS`** — sottostringhe separate da virgola; un alert
  viene soppresso se una di esse compare nel nome del container, nell'immagine,
  nella riga di comando o nella genealogia. La valvola di sfogo per i falsi
  positivi residui.
- **`KW_ALERT_MIN_SEVERITY`** continua a filtrare la consegna (vedi
  [configuration.md](configuration.md)).

## Limitazioni note

- **Race su argv/genealogia** — un processo dalla vita brevissima può uscire
  prima della lettura di `/proc`; le regole ripiegano allora sul solo percorso
  del binario.
- **Matching dei binari basato su liste** — una shell rinominata elude le liste,
  ma `container_drift` e `reverse_shell` (basate su argv) offrono copertura
  indipendente.
- **`container_drift`** segnala per ora solo l'esecuzione da percorsi
  scrivibili; il masquerade di argv[0] e il confronto con il manifest
  dell'immagine sono rimandati (genererebbero falsi positivi su login shell /
  busybox).

## Aggiungere una regola

Aggiungi un valore `Rule` in `internal/detector/rules.go` (id, severità, MITRE,
tag e una funzione `Match` che ritorna un `*hit` o `nil`) e registralo in
`defaultRules()`. Aggiungi un caso tabellare in `detector_test.go`. Vedi
[development.md](development.md).

## Roadmap

È pianificato un **motore di anomaly detection comportamentale** (baseline di
sequenze di syscall STIDE / n-gram per workload) a complemento di queste firme,
per intercettare attacchi sconosciuti — vedi [roadmap.md](roadmap.md).
