# ContainerSentry — Documentazione (Italiano)

ContainerSentry è un **sistema di rilevamento intrusioni a livello host (HIDS)
basato su eBPF** per container Docker. Aggancia le syscall Linux nello **spazio
kernel** e rileva comportamenti sospetti all'interno dei container in esecuzione
**senza installare alcun agente dentro i container stessi**.

Poiché il monitoraggio vive nel kernel, un attaccante che compromette un container
non può disattivarlo dall'interno.

> Il modulo Go si chiama `containersentry`. (Una build iniziale loggava la riga di
> avvio come "KernelWatch" — ora corretta in "ContainerSentry starting".)

## Indice della documentazione

| Documento | Cosa contiene |
|---|---|
| [overview.md](overview.md) | Cos'è il progetto, concetti chiave (eBPF, HIDS, ring buffer), maturità. |
| [architecture.md](architecture.md) | Come si incastrano i componenti, il flusso dati end-to-end, il layout binario dell'evento. |
| [components.md](components.md) | Riferimento file per file di ogni sorgente, con funzioni e struct principali. |
| [configuration.md](configuration.md) | Ogni variabile d'ambiente `CS_*`, valori di default e regole di validazione. |
| [detection-rules.md](detection-rules.md) | Le 6 regole di detection, cosa le attiva, severità e mappatura MITRE ATT&CK. |
| [deployment.md](deployment.md) | Deploy con Docker / Docker Compose, capability richieste, build da sorgente. |
| [development.md](development.md) | Build locale, generazione del codice eBPF, come aggiungere una regola o un hook syscall. |
| [roadmap.md](roadmap.md) | Roadmap, limitazioni note, stub e bug da tenere presenti. |

## In sintesi

- **Linguaggio:** Go 1.22 + eBPF (C), compilato tramite `bpf2go`.
- **Unica dipendenza:** `github.com/cilium/ebpf v0.15.0`.
- **Syscall agganciate:** `execve`, `openat`, `connect`, `clone`.
- **Rilevamenti:** shell nel container, tool di privilege escalation, accesso a file
  sensibili, tool di ricognizione di rete, package manager, accesso a file di credenziali.
- **Destinazioni alert:** file di log JSON, webhook (firmato HMAC-SHA256), Slack, stdout.
- **Requisiti:** kernel Linux 5.15+, root / capability eBPF. Build self-contained (niente BTF host).

## Avvio rapido

```bash
cp .env.example .env          # imposta almeno CS_SERVER_NAME e CS_API_TOKEN
docker compose up -d --build
docker compose logs -f containersentry
```

Vedi [deployment.md](deployment.md) per tutti i dettagli.
