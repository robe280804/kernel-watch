# Regole di detection

Il detector (`internal/detector/`) è **consapevole del contesto**: valuta ogni
evento non solo in base al binario coinvolto, ma in base a **chi lo ha avviato
(la genealogia dei processi)** e **con quali argomenti (argv)**. È questo che
distingue gli attacchi reali dalle normali operazioni: lo stesso `sh` o `curl` è
benigno se avviato da `cron` ed è un probabile web-shell se avviato da `nginx`.

Di default il detector valuta solo gli eventi dei **container**. Imposta
`KW_MONITOR_HOST=true` per monitorare anche l'**host Docker stesso** (processi
non appartenenti ad alcun container) — vedi
[Monitoraggio dell'host (intero server)](#monitoraggio-dellhost-intero-server)
più sotto. Ogni alert riporta uno `scope` pari a `container` o `host`.

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
  `httpd`, `php-fpm`, `node`, `java`, `puma`, `unicorn`, `gunicorn`, `uwsgi`,
  `mysqld`, `postgres`, `redis-server`, …) — **server daemon** esposti in rete.
  I runtime "nudi" (`php`, `python`, `ruby`) sono esclusi di proposito: un RCE
  web passa dal daemon (`php-fpm`), mentre l'interprete nudo è lo
  scheduler/queue/CLI (`php artisan`) e genererebbe falsi positivi.
  In caso di entrambi nella catena, **prevale network-facing**.

---

## Motore delle regole (YAML, stile Falco)

Le regole di detection sono **dati, non codice**. Un ruleset integrato è incluso
nel binario (`internal/ruleengine/default.yaml`); gli operatori estendono,
sovrascrivono o disabilitano le regole **senza ricompilare** puntando
`KW_RULES_FILE` (un file) o `KW_RULES_DIR` (una cartella di `*.yaml`, in ordine
lessicale) al proprio YAML, che viene **fuso sopra** i default. La tabella sotto è
il ruleset integrato di default.

Una regola è una condizione su un piccolo insieme di campi, una **matrice
lineage** opzionale e metadati:

```yaml
lists:
  shells: [sh, bash, zsh, dash, ash, ksh]
macros:
  spawns_shell: "evt.type = execve and in_list(proc.exe_base, $shells)"
rules:
  - id: shell_in_container
    scope: container            # container | host | all
    tactic: Execution
    technique: T1059
    tags: [container, shell]
    condition: spawns_shell
    lineage:                    # vince il primo arm che matcha; action:suppress => nessun alert
      - when: network
        severity: critical
        reason: "shell avviata da un servizio esposto in rete (RCE/web-shell)"
        details: { shell: proc.exe_base, spawned_by: lineage.network_parent }
      - when: trusted
        action: suppress
      - when: [unknown, interactive]
        severity: high
        reason: "esecuzione di shell nel container"
```

**DSL delle condizioni** — `and` / `or` / `not`, confronti (`=`, `!=`, `&`
bitmask-non-zero, `in`, `contains`, `startswith`), riferimenti `$lista`, letterali
`[..]` e helper: `in_list`, `chain_in_list`, `has_prefix`, `contains_any`,
`is_trusted_writer`, `is_docker_client`, `reverse_shell`.

**Campi** — `evt.type`, `evt.is_open_write`, `evt.is_open_trunc`, `proc.name`,
`proc.exe_base`, `proc.exe_path`, `proc.cmdline`, `proc.cmdline_lc`, `fd.name`,
`fd.directory`, `scope`, `lineage`, `lineage.network_parent`,
`container.name|id|image`, `ptrace.request`, `ptrace.target`, `bpf.cmd`.

**Matrice lineage** — ogni arm `lineage:` ha `when` (uno o più tra
`network`/`interactive`/`trusted`/`unknown`/`any`), un `and:` di guardia opzionale
e o `action: suppress` o `severity`+`reason`(+`details`). Una regola con arm ma
senza match è soppressa; una regola senza arm usa la sua `severity`/`reason`
top-level. È così che un'unica regola eleva o silenzia in base all'ascendenza —
esattamente il comportamento delle regole Go originali, ora dichiarativo.

**Flusso operatore**
- **Override / append / add** — una regola overlay con `override: true` sostituisce
  per id una regola gestita; `append: true` ne estende `tags`/`exceptions`;
  `enabled: false` la disabilita; un id nuovo aggiunge una regola. `append_lists:`
  estende una lista integrata.
- **Eccezioni** — carve-out per-regola stile Falco (`{name, fields, comps, values}`),
  valutate dopo il match, in aggiunta alla REST API di soppressione a runtime.
- **Validazione** — `kernelwatch --validate` compila il ruleset integrato +
  operatore ed esce 0/1 (senza root né eBPF — ideale per la CI).
- **Hot reload** — quando è configurato un ruleset personalizzato, viene ricaricato
  a intervalli brevi; un file rotto **fallisce subito all'avvio** ma un hot reload
  rotto mantiene l'ultimo ruleset valido, così il monitor non si disarma mai.

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

## Monitoraggio dell'host (intero server)

Con `KW_MONITOR_HOST=true`, KernelWatch sorveglia anche l'**host Docker stesso**:
un attaccante che approda sull'host (non in un container) è il bersaglio più
prezioso. Il monitoraggio dell'host è **opt-in e a impatto nullo se disattivo**:
gli eventi dell'host vengono scartati nel collector, quindi un deployment
solo-container esistente resta identico al bit.

**Rollout (per host):** abilita con `KW_MODE=monitor` per ~48h di tuning, regola
le liste `KW_HOST_*` su ciò che osservi, poi torna a `KW_MODE=alert`. Interroga i
rilevamenti host con `GET /api/v1/alerts?scope=host`.

### Controllo del rumore sull'host

Le syscall dell'host scattano ordini di grandezza più spesso di quelle dei
container. Invece della **denylist** dei container, gli eventi host attraversano
una **allowlist** nel collector (`internal/collector/hostfilter.go`):

- **`openat`** — recapitati solo per percorsi rilevanti per la sicurezza (cron,
  unit systemd, `ld.so.preload`, config ssh/sudoers/pam, `/var/log`,
  `docker.sock`, `authorized_keys`, credenziali cloud…). Percorsi extra via
  `KW_HOST_OPEN_WATCH_EXTRA`.
- **`connect`/`clone`** — scartati (nessuna regola host li consuma in v1).
- **`execve`** — mantenuti, esclusi gli agent di flotta elencati in
  `KW_HOST_EXEC_EXCLUDE` (es. `node_exporter`, `datadog-agent`).
- Il **PID di KernelWatch** è sempre escluso.

Gli open host in allowlist (basso volume) vengono poi arricchiti con la
genealogia come gli execve, così le regole sui file host distinguono uno
**scrittore fidato** (`dpkg`, `apt`, `systemd`, `cloud-init`, `logrotate`,
`dockerd`…; estendibile via `KW_HOST_TRUSTED_WRITERS`) da un attaccante.

### Genealogia sull'host

Una nuova classe si aggiunge a trusted/network-facing: **sessione amministrativa
interattiva** (la genealogia contiene `sshd`/`login`/`getty`/`tmux`/`screen`).
`sudo` sotto `sshd` è operatività quotidiana (soppresso); `sudo` sotto `nginx` è
un incidente. La genealogia network-facing prevale comunque su tutto. Genitori
fidati solo-host extra via `KW_HOST_TRUSTED_PARENTS`.

### Regole esistenti sull'host

`reverse_shell` scatta ovunque. `kernel_module_load`/`bpf_prog_load` sopprimono
la genealogia fidata (init/udev/dkms; dockerd/containerd) e sono High.
`persistence` aggiunge percorsi host e sopprime gli scrittori fidati.
`sensitive_file` richiede **intento di scrittura** sull'host (le letture di
`/etc/passwd` ecc. sono costanti). `credential_file` usa il match per sottostringa
così `/home/*/.aws/credentials` viene intercettato. `network_tool`/
`privilege_escalation` sopprimono `curl`/`sudo` in sessione interattiva (ma
`nmap`/`masscan`/strumenti di namespace scattano comunque). `package_manager`
sull'host scatta **solo** con genealogia network (Critical). `shell_in_container`
e `container_drift` restano solo-container (analoghi host sotto).

### Nuove regole host

| Id regola | Trigger | Severità | MITRE |
|-----------|---------|----------|-------|
| `host_user_manipulation` | `execve` di `useradd`/`usermod`/`chpasswd`/`passwd`/… | interattiva → Low, network → **Critical**, altrimenti Medium | T1136.001 |
| `host_log_tampering` | `shred`/`wipe` di `wtmp`/`btmp`/`*_history`; troncamento/modifica di `/var/log` da un non-logger | Medium–High | T1070 |
| `host_docker_sock` | `/var/run/docker.sock` aperto da un processo non-Docker (estendi via `KW_HOST_DOCKER_CLIENTS`) | High | T1610 |
| `host_tmp_exec` | `execve` da `/tmp`, `/dev/shm`, `/var/tmp` (non `/run` — lo usa systemd); genealogia di build/pacchetti soppressa | High | T1204.002 |
| `host_shell_from_service` | `execve` di shell con genealogia network sull'host (RCE su nginx/node/java sull'host) | **Critical** | T1059 |

### Brute-force SSH (tailer del log di auth)

eBPF non può vedere gli **esiti** dell'autenticazione, quindi il
credential-stuffing SSH è rilevato leggendo il log di auth dell'host
(`internal/logtail/`). Abilita con `KW_AUTHLOG_ENABLED=true` e punta
`KW_AUTHLOG_PATH` al log (il file Compose monta `/var/log → /hostlog:ro`; usa
`/hostlog/auth.log` su Debian/Ubuntu o `/hostlog/secure` su RHEL). Mantiene una
finestra scorrevole per IP sorgente e sintetizza un alert host `ssh_bruteforce`
(T1110.001) dopo `KW_SSH_BRUTE_THRESHOLD` fallimenti entro
`KW_SSH_BRUTE_WINDOW` secondi, nella stessa pipeline alert/correlazione/SIEM
degli eventi eBPF.

### Delegato al livello SIEM

KernelWatch deliberatamente **non** fa, lasciandolo allo stack circostante:
**hashing** di integrità file (trappola TOCTOU/performance — le regole di
persistenza con intento di scrittura sono il 20% ad alto segnale; usa
Wazuh/osquery per il FIM completo), **CIS benchmark / SCA**
(docker-bench-security / OpenSCAP) e **vulnerability scanning** (Trivy/Grype).

---

## Correlazione delle catene d'attacco

Una singola syscall sospetta è spesso ambigua; una **sequenza** di esse
dallo stesso albero di processi di un container è un'intrusione in corso. Il
correlatore (`internal/correlator/`) mantiene una breve finestra scorrevole di
rilevamenti per container, assegna a ciascuno un punteggio in base alla severità
(punti di rischio: low=10, medium=25, high=50, critical=100) e traccia le
**fasi distinte della kill-chain MITRE ATT&CK** raggiunte.

Quando un container supera una soglia — `KW_CORRELATION_MIN_STAGES` fasi
distinte **oppure** `KW_CORRELATION_MIN_SCORE` di rischio accumulato entro
`KW_CORRELATION_WINDOW` — viene emesso **un unico incidente `attack_chain`**:

- severità **High**, che sale a **Critical** man mano che la catena si allarga;
- una descrizione che elenca le fasi in ordine (es. *Execution → Discovery →
  Credential Access → Persistence*) e il punteggio di rischio;
- `details` con gli id delle regole coinvolte, l'elenco delle fasi, il numero di
  rilevamenti e la finestra;
- etichettato `attack-chain` — gli incidenti **bypassano** il filtro di severità
  e il rate limiter, quindi non vengono mai scartati, e sono riemessi solo quando
  una **nuova** fase si aggiunge alla catena (`KW_CORRELATION_COOLDOWN` evita il
  flapping).

Questo aumenta la confidenza sui veri positivi e riduce l'alert fatigue:
l'operatore vede la campagna, non 30 righe scollegate. Il motore è
completamente deterministico e spiegabile — nessuna fase di apprendimento.
Disattivabile con `KW_CORRELATION_ENABLED=false`.

## Soppressione dei falsi positivi

Tre livelli deterministici, applicati in ordine:

1. **Contesto di genealogia** (sopra) — sopprime l'attività benigna per ascendenza.
2. **Eccezioni di configurazione** (`KW_DETECTION_EXCEPTIONS`) — match su
   sottostringa di nome/immagine/cmdline/ascendenza; sopprime **tutte** le regole
   per quell'evento.
3. **Regole di soppressione dell'operatore** (`internal/suppress/`) — filtri
   strutturati per falsi positivi su `(rule_id, container_name, process_name,
   sottostringa)`, in AND, così che una regola più specifica silenzi di meno.
   `scope` e `hostname` **restringono** ulteriormente una regola (non possono
   stare da soli — niente silenziamento in blocco di un intero scope o host);
   `hostname` conta perché una flotta condivide un solo database, quindi
   silenziare un host rumoroso non deve zittire gli altri. Vengono sostituite nel
   detector in modo atomico e consultate prima della deduplica, così un
   rilevamento soppresso non occupa nemmeno uno slot di deduplica, e sono gestite
   a runtime tramite la REST API.

In aggiunta: **deduplica** a finestra breve per `(regola, container, pid)` e
**rate limiting** per container (`KW_ALERT_MAX_RATE`/`KW_ALERT_RATE_WINDOW`).

## Formato di output (SIEM)

`KW_ALERT_FORMAT` seleziona il formato per il file di log e il corpo del webhook:
`native` (JSON KernelWatch arricchito, default) o `ecs`
([Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/)). ECS
mappa i dati MITRE su `threat.*` e porta gli extra sotto `kernelwatch.*`, per
l'ingestione diretta in Elastic Security e in qualsiasi SIEM compatibile con ECS.

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
