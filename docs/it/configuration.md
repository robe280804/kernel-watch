# Riferimento configurazione

Tutta la configurazione avviene tramite **variabili d'ambiente**, caricate e validate
da `internal/config/config.go`. Non ci sono file di configurazione: si fa il deploy
della stessa immagine ovunque e si cambia solo il `.env`. Copia `.env.example` in
`.env` per iniziare.

## Variabili

### Identità del server e modalità

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_SERVER_NAME` | string | `kernelwatch-host` | Nome host leggibile; appare in ogni alert (`server_name`). |
| `KW_MODE` | enum | `alert` | `alert` valuta le regole e invia gli alert; `monitor` è dry-run (le regole vengono valutate e loggate ma webhook/Slack non vengono mai chiamati). Validata. |

### Ruleset di detection (YAML)

Le regole di detection sono **dati, non codice**: un ruleset di base è incorporato
nel binario e questi overlay vengono fusi sopra di esso (sovrascrivi una regola per
id, `append: true` per estenderne tag/eccezioni, oppure aggiungi nuove regole) —
nessuna ricompilazione. Vedi [detection-rules.md](detection-rules.md) per il DSL.
Valida un ruleset senza root né eBPF con `kernelwatch --validate` (ideale per la CI).

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_RULES_FILE` | string | _(vuoto)_ | Un singolo file overlay YAML fuso sui default. Validato come file leggibile. |
| `KW_RULES_DIR` | string | _(vuoto)_ | Una directory di overlay `*.yaml`/`*.yml`, applicati in ordine lessicale. Validata come directory. |

### Tuning della detection basata sulla lineage

La detection è context-aware: lo stesso binario (`sh`, `curl`, `apt`) è benigno o
malevolo a seconda della sua ancestry di processo.

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_ANCESTRY_DEPTH` | int | `5` | Processi antenati da risolvere per ogni execve. Valori `≤ 0` ignorati (resta il default). |
| `KW_TRUSTED_PARENTS` | CSV | _(vuoto)_ | Nomi di processi padre aggiuntivi trattati come supervisori/scheduler benigni, oltre ai built-in (init, systemd, cron, containerd-shim, tini…). |
| `KW_NETWORK_PARENTS` | CSV | _(vuoto)_ | Nomi di processi padre aggiuntivi trattati come network-facing (superficie d'attacco), oltre ai built-in (nginx, apache2, php-fpm, node, java…). |
| `KW_DETECTION_EXCEPTIONS` | CSV | _(vuoto)_ | Sopprime qualsiasi alert il cui nome container, immagine, cmdline o ancestry contiene una di queste sottostringhe. |

### Monitoraggio host (intero server)

Opt-in. Quando `KW_MONITOR_HOST=false` (default) ogni evento host viene scartato dal
collector e il comportamento è identico alla build solo-container. Vedi
[detection-rules.md](detection-rules.md) per il ruleset host.

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_MONITOR_HOST` | bool | `false` | Estende la detection dai container all'host Docker stesso. |
| `KW_HOST_OPEN_WATCH_EXTRA` | CSV | _(vuoto)_ | Prefissi/sottostringhe di path `openat` host aggiuntivi da osservare, oltre al set di sicurezza built-in. |
| `KW_HOST_EXEC_EXCLUDE` | CSV | _(vuoto)_ | Nomi comm da escludere dal monitoraggio execve host (agent di flotta come node_exporter, datadog-agent…). |
| `KW_HOST_TRUSTED_WRITERS` | CSV | _(vuoto)_ | Processi aggiuntivi trattati come writer fidati dei path di persistenza/config host (oltre a dpkg/apt/rpm/dnf/snapd/systemd/cloud-init/logrotate/dockerd…). |
| `KW_HOST_TRUSTED_PARENTS` | CSV | _(vuoto)_ | Comm padre benigni aggiuntivi per la sola classificazione host-scope (fusi sopra la lista trusted-parents dei container). |
| `KW_HOST_DOCKER_CLIENTS` | CSV | _(vuoto)_ | Nomi comm aggiuntivi autorizzati ad aprire `/var/run/docker.sock` sull'host senza far scattare `host_docker_sock`. |

### Soglie e formato degli alert

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_ALERT_MIN_SEVERITY` | enum | `medium` | Severità minima da emettere: `low` / `medium` / `high` / `critical`. Validata. (Gli incidenti correlati la bypassano.) |
| `KW_ALERT_MAX_RATE` | int | `10` | Max alert per container nella finestra di rate. |
| `KW_ALERT_RATE_WINDOW` | int (s) | `60` | Lunghezza della finestra scorrevole per il rate limiting. |
| `KW_ALERT_FORMAT` | enum | `native` | Formato wire per il file di log e i body webhook: `native` (JSON KernelWatch arricchito) o `ecs` (Elastic Common Schema). Slack usa sempre il formato human-readable. Validata. |

### Correlazione attack-chain

I finding indipendenti dell'albero di processi di un container che attraversano più
stadi della kill-chain MITRE entro la finestra vengono consolidati in un unico
incidente escalato. Gli incidenti correlati bypassano il filtro severità/rate.

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_CORRELATION_ENABLED` | bool | `true` | Abilita la correlazione attack-chain. |
| `KW_CORRELATION_WINDOW` | int (s) | `300` | Finestra scorrevole su cui i finding di un container sono correlati. Valori `≤ 0` ignorati. |
| `KW_CORRELATION_MIN_STAGES` | int | `3` | Stadi distinti della kill-chain richiesti per generare un incidente. Valori `≤ 0` ignorati. |
| `KW_CORRELATION_MIN_SCORE` | int | `120` | OPPURE: punteggio di rischio accumulato richiesto (punti: low=10, medium=25, high=50, critical=100). Valori `≤ 0` ignorati. |
| `KW_CORRELATION_COOLDOWN` | int (s) | `300` | Secondi minimi tra incidenti per lo stesso container (anti-flap). Valori `< 0` ignorati. |
| `KW_CORRELATION_HOST_MIN_STAGES` | int | `0` (eredita) | Override host per gli stadi minimi. `0` = eredita il valore container. |
| `KW_CORRELATION_HOST_MIN_SCORE` | int | `0` (eredita) | Override host per lo score minimo. `0` = eredita il valore container. |

### Rilevamento brute-force SSH (tailer dell'auth-log)

eBPF non può vedere gli esiti dell'autenticazione, quindi il credential-stuffing SSH
viene rilevato leggendo l'auth log dell'host. Opt-in. Sintetizza alert host-scope
`ssh_bruteforce` (MITRE T1110.001).

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_AUTHLOG_ENABLED` | bool | `false` | Abilita il tailer dell'auth-log. |
| `KW_AUTHLOG_PATH` | string | `/var/log/auth.log` | Auth log da seguire (Debian/Ubuntu `auth.log`, RHEL/CentOS `secure`; in Docker monta il log host in sola lettura). |
| `KW_SSH_BRUTE_THRESHOLD` | int | `5` | Tentativi falliti da un IP sorgente entro la finestra prima di allertare. Valori `≤ 0` ignorati. |
| `KW_SSH_BRUTE_WINDOW` | int (s) | `60` | Finestra scorrevole per il conteggio brute-force. Valori `≤ 0` ignorati. |

### Destinazioni degli alert

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_LOG_ENABLED` | bool | `true` | Scrive gli alert nel file di log JSON. |
| `KW_LOG_PATH` | string | `/var/log/kernelwatch/alerts.json` | Percorso del log degli alert (directory creata automaticamente). |
| `KW_LOG_MAX_MB` | int | `50` | Ruota il log degli alert oltre questa dimensione; `0` disabilita la rotazione. |
| `KW_LOG_MAX_BACKUPS` | int | `3` | Backup ruotati da mantenere (`alerts.json.1…N`). |
| `KW_WEBHOOK_ENABLED` | bool | `false` | Abilita la consegna via webhook. |
| `KW_WEBHOOK_URL` | string | — | Endpoint webhook. **Obbligatorio** se il webhook è abilitato. |
| `KW_WEBHOOK_SECRET` | string | — | Chiave di firma HMAC-SHA256. Se vuota, le richieste non sono firmate. |
| `KW_SLACK_ENABLED` | bool | `false` | Abilita la consegna su Slack. |
| `KW_SLACK_WEBHOOK_URL` | string | — | Incoming webhook Slack. **Obbligatorio** se Slack è abilitato. |
| `KW_SLACK_CHANNEL` | string | `#security-alerts` | Canale Slack. |

### REST API

API autenticata di lettura/gestione per lo storico di alert e incidenti e per le
soppressioni operative. Disabilitata di default (superficie di rete opt-in); gli
endpoint dati richiedono `KW_DB_ENABLED=true`. Vedi [README.md](../../README.md) per
l'elenco degli endpoint.

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_API_ENABLED` | bool | `false` | Espone la REST API. |
| `KW_API_BIND_ADDR` | string | `127.0.0.1` | Interfaccia su cui fare il bind. **Tienila su loopback** a meno di frontarla con TLS + controlli di rete — è HTTP in chiaro. |
| `KW_API_PORT` | int | `8080` | Porta REST API. Validata 1–65535. |
| `KW_API_TOKEN` | string | — | Bearer token. **Obbligatorio quando `KW_API_ENABLED=true`**: ≥16 caratteri, non deve contenere `changeme`. Confrontato in tempo costante. |

### eBPF, health e database

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `KW_EBPF_RINGBUF_SIZE` | int (byte) | `16777216` (16 MB) | Dimensione del ring buffer, applicata al load eBPF. Potenza di due, multiplo della page size. Aumentala se `kernel_drops` cresce nel log delle stats. |
| `KW_HEALTH_FILE` | string | `/var/log/kernelwatch/health` | File di heartbeat scritto dal demone e controllato da `kernelwatch -health`. |
| `KW_DB_ENABLED` | bool | `false` | Salva gli alert su TimescaleDB. docker-compose lo imposta a `true`. Best-effort: un DB non raggiungibile non blocca mai il monitoraggio. |
| `KW_DB_RETENTION_DAYS` | int | `90` | Elimina automaticamente gli alert più vecchi di N giorni (retention TimescaleDB). `0` = conserva per sempre. |
| `KW_DB_HOST` | string | `localhost` | Host TimescaleDB. |
| `KW_DB_PORT` | int | `5432` | Porta TimescaleDB. |
| `KW_DB_NAME` | string | `kernelwatch` | Nome database. |
| `KW_DB_USER` | string | `kernelwatch` | Utente database. |
| `KW_DB_PASSWORD` | string | — | Password database. **Obbligatoria quando `KW_DB_ENABLED=true`; il demone non parte se vuota o lasciata a `changeme`.** |
| `KW_DB_SSL_MODE` | string | `disable` | `sslmode` per il DSN. |

> I valori CSV vengono divisi sulle virgole e trimmati; le voci vuote sono scartate. I
> booleani usano `strconv.ParseBool` di Go (`true/false/1/0/t/f`…); un valore non
> parsabile ripiega sul default. Anche gli interi non parsabili ripiegano sul default
> (il valore errato viene segnalato ma non è fatale).

## Regole di validazione (`Config.validate`)

Il caricamento **fallisce** (il processo esce) se una di queste è violata:

- `KW_ALERT_MIN_SEVERITY` non è uno tra `low/medium/high/critical`.
- `KW_MODE` non è `alert` o `monitor`.
- `KW_ALERT_FORMAT` non è `native` o `ecs`.
- `KW_DB_ENABLED=true` ma `KW_DB_PASSWORD` è vuota o lasciata a `changeme`.
- `KW_API_PORT` è fuori da 1–65535.
- `KW_API_ENABLED=true` ma `KW_API_TOKEN` è vuoto, più corto di 16 caratteri o
  contiene `changeme`.
- `KW_RULES_FILE` è impostato ma non è un file leggibile.
- `KW_RULES_DIR` è impostato ma non è una directory.
- `KW_WEBHOOK_ENABLED=true` ma `KW_WEBHOOK_URL` è vuoto.
- `KW_SLACK_ENABLED=true` ma `KW_SLACK_WEBHOOK_URL` è vuoto.

## Comportamento del filtraggio (`Config.IsMonitored`)

```
se name in blacklist            → NON monitorato
altrimenti se whitelist non vuota → monitorato solo se name in whitelist
altrimenti                       → monitorato
```

Il matching è case-insensitive. Il "nome" del container passato qui è quello che il
mapper ha risolto — attualmente lo **short ID di 12 caratteri** (perché `dockerInspect`
è uno stub), quindi whitelist/blacklist per nome funzionano in modo affidabile solo
una volta implementato l'arricchimento via Docker API.

## DSN del database

`Config.DSN()` produce:

```
host=<H> port=<P> dbname=<N> user=<U> password=<PW> sslmode=<M>
```

Il layer di storage (`internal/storage`) e la REST API usano entrambi questo DSN
quando `KW_DB_ENABLED=true`.

## Note di sicurezza

- `KW_WEBHOOK_SECRET`, `KW_API_TOKEN` e `KW_DB_PASSWORD` sono variabili d'ambiente in
  chiaro. In produzione preferisci i secret di Docker/Swarm o un secrets manager,
  iniettandoli a runtime invece di committare un `.env` reale.
- Il file Compose binda Postgres solo su `127.0.0.1:5432` — mantienilo così.
- La REST API fa il bind su `127.0.0.1` di default e **si rifiuta di partire** senza
  un `KW_API_TOKEN` forte (≥16 caratteri, niente `changeme`) quando abilitata — non
  esiste una modalità "auth disabilitata". È HTTP in chiaro, quindi imposta
  `KW_API_BIND_ADDR` su un indirizzo non-loopback solo dietro un reverse proxy con
  terminazione TLS e controlli di rete.
