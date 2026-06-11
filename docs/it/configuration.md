# Riferimento configurazione

Tutta la configurazione avviene tramite **variabili d'ambiente**, caricate e validate
da `internal/config/config.go`. Non ci sono file di configurazione: si fa il deploy
della stessa immagine ovunque e si cambia solo il `.env`. Copia `.env.example` in
`.env` per iniziare.

## Variabili

| Variabile | Tipo | Default | Descrizione |
|---|---|---|---|
| `CS_SERVER_NAME` | string | `containersentry-host` | Nome host leggibile; appare in ogni alert (`server_name`). |
| `CS_CONTAINER_WHITELIST` | CSV | _(vuoto = tutti)_ | Se impostata, vengono monitorati **solo** questi nomi di container. |
| `CS_CONTAINER_BLACKLIST` | CSV | _(vuoto)_ | Nomi di container da ignorare. La blacklist vince sempre sulla whitelist. |
| `CS_ALERT_MIN_SEVERITY` | enum | `medium` | Severità minima da emettere: `low` / `medium` / `high` / `critical`. Validata. |
| `CS_ALERT_MAX_RATE` | int | `10` | Max alert per container nella finestra di rate. |
| `CS_ALERT_RATE_WINDOW` | int (s) | `60` | Lunghezza della finestra scorrevole per il rate limiting. |
| `CS_LOG_ENABLED` | bool | `true` | Scrive gli alert nel file di log JSON. |
| `CS_LOG_PATH` | string | `/var/log/containersentry/alerts.json` | Percorso del log degli alert (directory creata automaticamente). |
| `CS_WEBHOOK_ENABLED` | bool | `false` | Abilita la consegna via webhook. |
| `CS_WEBHOOK_URL` | string | — | Endpoint webhook. **Obbligatorio** se il webhook è abilitato. |
| `CS_WEBHOOK_SECRET` | string | — | Chiave di firma HMAC-SHA256. Se vuota, le richieste non sono firmate. |
| `CS_SLACK_ENABLED` | bool | `false` | Abilita la consegna su Slack. |
| `CS_SLACK_WEBHOOK_URL` | string | — | Incoming webhook Slack. **Obbligatorio** se Slack è abilitato. |
| `CS_SLACK_CHANNEL` | string | `#security-alerts` | Canale Slack. |
| `CS_API_PORT` | int | `8080` | Porta REST API. Validata 1–65535. *(API non ancora implementata.)* |
| `CS_API_TOKEN` | string | — | Bearer token per la futura API. |
| `CS_EBPF_RINGBUF_SIZE` | int (byte) | `16777216` (16 MB) | Dimensione del ring buffer. *(Letta nella config ma non ancora applicata al load — vedi roadmap.)* |
| `CS_DB_HOST` | string | `localhost` | Host TimescaleDB. |
| `CS_DB_PORT` | int | `5432` | Porta TimescaleDB. |
| `CS_DB_NAME` | string | `containersentry` | Nome database. |
| `CS_DB_USER` | string | `containersentry` | Utente database. |
| `CS_DB_PASSWORD` | string | — | Password database. |
| `CS_DB_SSL_MODE` | string | `disable` | `sslmode` per il DSN. |

> I valori CSV vengono divisi sulle virgole e trimmati; le voci vuote sono scartate. I
> booleani usano `strconv.ParseBool` di Go (`true/false/1/0/t/f`…); un valore non
> parsabile ripiega sul default.

## Regole di validazione (`Config.validate`)

Il caricamento **fallisce** (il processo esce) se una di queste è violata:

- `CS_ALERT_MIN_SEVERITY` non è uno tra `low/medium/high/critical`.
- `CS_API_PORT` è fuori da 1–65535.
- `CS_WEBHOOK_ENABLED=true` ma `CS_WEBHOOK_URL` è vuoto.
- `CS_SLACK_ENABLED=true` ma `CS_SLACK_WEBHOOK_URL` è vuoto.

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

È pronto all'uso ma nessun componente apre ancora una connessione al DB.

## Note di sicurezza

- `CS_WEBHOOK_SECRET`, `CS_API_TOKEN` e `CS_DB_PASSWORD` sono variabili d'ambiente in
  chiaro. In produzione preferisci i secret di Docker/Swarm o un secrets manager,
  iniettandoli a runtime invece di committare un `.env` reale.
- Il file Compose binda Postgres solo su `127.0.0.1:5432` — mantienilo così.
- Imposta un `CS_API_TOKEN` forte e casuale prima che l'API arrivi; un token vuoto è
  inteso come "auth disabilitata" (sconsigliato).
