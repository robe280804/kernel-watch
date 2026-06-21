# Dashboard

KernelWatch include una **dashboard web** opzionale — una piccola app
[Next.js](https://nextjs.org) (in [`dashboard/`](../../dashboard)) che offre una vista
visuale sullo storico degli alert e permette di gestire le soppressioni dei falsi
positivi, senza dover interrogare TimescaleDB a mano o leggere `alerts.json`.

È una UI sottile sopra la [REST API](configuration.md#rest-api) esistente: **non** parla
direttamente con il database e non aggiunge alcun privilegio al daemon.

## Architettura

```
Browser ──> route handler Next.js (BFF, custodisce KW_API_TOKEN) ──> REST API KernelWatch (Bearer)
```

Il browser chiama esclusivamente le rotte `/api/*` della dashboard stessa. Quegli handler
**lato server** iniettano l'header Bearer `KW_API_TOKEN` e fanno da proxy verso l'API di
KernelWatch. Il token non raggiunge mai il browser e l'API di KernelWatch resta in ascolto
solo su loopback.

## Prerequisiti

La dashboard è inutile senza l'API e il database del daemon, quindi sul **daemon** imposta:

| Variabile | Valore richiesto | Perché |
|---|---|---|
| `KW_API_ENABLED` | `true` | Avvia la REST API che la dashboard legge. Disattivata di default. |
| `KW_API_TOKEN` | un valore casuale forte | Segreto condiviso. Deve essere ≥16 caratteri e **non** contenere `changeme` (altrimenti il daemon si rifiuta di avviarsi). Generane uno: `openssl rand -hex 32`. |
| `KW_DB_ENABLED` | `true` | Gli endpoint `/alerts` e `/stats` interrogano TimescaleDB. Compose lo imposta a `true` di default. |

Il daemon **e** la dashboard leggono lo stesso `KW_API_TOKEN`, quindi impostarlo una volta
sola in `.env` li mantiene allineati (Compose lo passa anche al servizio dashboard).

## Avvio (Docker Compose)

Il servizio `dashboard` è già configurato in `docker-compose.yml`. Dalla radice del repo:

```bash
# 1. abilita l'API + imposta un token forte in .env
TOKEN=$(openssl rand -hex 32)
sed -i "s|^KW_API_TOKEN=.*|KW_API_TOKEN=$TOKEN|" .env
grep -q '^KW_API_ENABLED=' .env \
  && sed -i 's|^KW_API_ENABLED=.*|KW_API_ENABLED=true|' .env \
  || echo 'KW_API_ENABLED=true' >> .env

# 2. (ri)crea daemon e dashboard così entrambi prendono i nuovi valori
docker compose up -d --build kernelwatch dashboard

# 3. verifica che l'API sia in ascolto e la dashboard sia su
docker compose logs --tail=20 kernelwatch    # atteso "REST API listening"
docker compose ps dashboard                  # atteso "Up (healthy)"
```

### Cosa fa il servizio Compose

- `build: ./dashboard` — costruisce l'immagine standalone di Next.js.
- `network_mode: host` — necessario perché la dashboard raggiunga l'API del daemon su
  `127.0.0.1:8080` (l'API è in ascolto sul loopback dell'host, irraggiungibile da una rete
  bridge).
- Si lega a `127.0.0.1:${DASHBOARD_PORT:-3000}` (`HOSTNAME=127.0.0.1`), quindi la UI è
  **solo su loopback** — non esposta sulle interfacce pubbliche dell'host.
- `mem_limit: 256m`, `restart: unless-stopped` e un healthcheck che interroga la propria
  pagina principale.

## Come accedervi

Poiché la dashboard è legata al loopback sul server, non puoi raggiungerla direttamente da
un'altra macchina — è voluto (può modificare le soppressioni, quindi non deve essere esposta
pubblicamente). Due opzioni:

### Tunnel SSH (consigliato per l'uso quotidiano)

Dalla tua postazione, inoltra una porta locale verso il loopback del server:

```bash
ssh -L 3000:127.0.0.1:3000 <utente>@<server>
```

Tieni aperta la sessione e apri <http://127.0.0.1:3000>. Chiudere la sessione SSH chiude il
tunnel. Se la porta locale 3000 è occupata, usane un'altra, es. `-L 8088:127.0.0.1:3000`,
poi apri `http://127.0.0.1:8088`.

### Reverse proxy + TLS (per accesso permanente)

Metti un reverse proxy (Caddy, nginx, Traefik) sul server che termina HTTPS e fa da proxy
verso `127.0.0.1:3000`. Tieni la dashboard stessa sul loopback; solo il proxy si affaccia
sulla rete. Proteggila con **la sua autenticazione** (e idealmente VPN / allowlist di IP) —
la dashboard può aggiungere ed eliminare soppressioni, quindi va trattata come una
superficie di controllo.

## Cosa puoi fare dalla dashboard

### Panoramica (Overview)

Conteggi aggregati su una finestra temporale selezionabile (1h / 24h / 7g / 30g), serviti
da `/api/v1/stats`:

- **Totale alert** e una riga di card per severità.
- Barre di ripartizione: **per severità**, **per scope** (host vs container), **per regola**
  e **top container**.

È la vista d'insieme "quanto è rumoroso il mio parco macchine, e dove".

### Alert e incidenti

Una tabella filtrabile dello storico alert (`/api/v1/alerts`). Filtri: finestra temporale
(`since`), **scope**, **severità**, **container**, **regola** e **limite**. Ogni riga mostra
i campi che distinguono un finding reale dal rumore benigno:

- timestamp (UTC), badge di severità, badge di scope (host/container)
- id regola, nome container, **nome processo**, **nome padre**
- il motivo, più la **command line** / `details` (es. lo strumento, il file toccato)

Anche gli **incidenti di catena d'attacco** correlati (`rule_id = attack_chain`) appaiono
qui — filtra per regola `attack_chain` per vedere solo gli incidenti.

### Soppressioni

Elenca, aggiungi ed elimina il modello operatore dei falsi positivi
(`/api/v1/suppressions`). È la superficie di **"impostazioni" regolabili a caldo**: le
modifiche hanno effetto immediato perché il daemon ricarica a caldo l'insieme delle
soppressioni — nessun riavvio.

Una soppressione corrisponde a un alert solo quando **ogni** campo impostato corrisponde
(i campi sono in AND, quindi una regola più specifica silenzia di meno). Imposta **almeno
un** campo primario:

- `rule_id` (es. `network_tool`), `container_name`, `process_name`, oppure `substr`
  (match case-insensitive su nome / immagine / cmdline / ancestry).
- `scope` e `hostname` servono solo a **restringere** una regola esistente — non possono
  stare da soli (così si evita una regola "silenzia tutti gli alert host" indiscriminata).

**Esempio — silenziare un `curl` di healthcheck che continua a far scattare `network_tool`
sull'host:** nella pagina Soppressioni imposta Rule ID `network_tool`, Process name `curl`,
Scope `host` e una nota nel Reason, poi *Add*. Gli alert corrispondenti (e qualsiasi
incidente `attack_chain` costruito da essi) si fermano immediatamente.

> Le soppressioni sono lo strumento giusto per i falsi positivi. Per una messa a punto più
> profonda (soglie, parent fidati, punteggi di correlazione, abilitazione del monitoraggio
> host) modifica le variabili `KW_*` in `.env` e riavvia — vedi
> [configuration.md](configuration.md).

## Variabili d'ambiente

Lette dal servizio dashboard (vedi [configuration.md](configuration.md) per l'elenco
completo):

| Variabile | Default | Scopo |
|---|---|---|
| `KW_API_URL` | `http://127.0.0.1:8080` | Dove il server della dashboard raggiunge l'API di KernelWatch. |
| `KW_API_TOKEN` | *(obbligatorio)* | Token Bearer; deve coincidere con il `KW_API_TOKEN` del daemon. |
| `DASHBOARD_PORT` | `3000` | Porta su cui la dashboard è in ascolto (legata a `127.0.0.1`). |

## Risoluzione dei problemi

| Sintomo | Causa e soluzione |
|---|---|
| `ERR_CONNECTION_REFUSED` nel browser | Nessuno è in ascolto a quell'indirizzo sulla **tua** macchina. Stai aprendo `127.0.0.1` sulla tua postazione ma la dashboard gira sul server — apri il tunnel SSH qui sopra. |
| La pagina si carica ma i grafici mostrano un **banner d'errore** | La dashboard ha raggiunto il server ma l'API non ha risposto. Verifica `KW_API_ENABLED=true`, che il `KW_API_TOKEN` della dashboard coincida con quello del daemon e che il daemon abbia loggato `REST API listening`. |
| I grafici si caricano ma sono **vuoti** | Nessun alert nella finestra selezionata, oppure `KW_DB_ENABLED=false` (gli endpoint dati restituiscono 503). Allarga la finestra o abilita la persistenza. |
| Il daemon si rifiuta di avviarsi dopo aver abilitato l'API | `KW_API_TOKEN` manca, è troppo corto (<16 caratteri) o contiene ancora `changeme`. Imposta un token forte. |

## Build / sviluppo locale

```bash
cd dashboard
npm install
KW_API_URL=http://127.0.0.1:8080 KW_API_TOKEN=<token> npm run dev
```

Vedi [`dashboard/README.md`](../../dashboard/README.md) per la struttura dei file. I tipi
TypeScript in `dashboard/lib/types.ts` rispecchiano le forme dell'API Go (`internal/alerter`,
`internal/storage`, `internal/suppress`) e vanno mantenuti allineati ad esse.
