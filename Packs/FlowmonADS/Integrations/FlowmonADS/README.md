# Flowmon ADS

Integrates with **Progress Flowmon Anomaly Detection System (ADS)** REST API to ingest network anomaly events as XSIAM alerts and enrich investigations with flow-based threat intelligence.

## Authentication

The integration uses **OAuth2 Password Grant** to authenticate against the Flowmon REST API:

- Token URL: `https://<flowmon-host>/resources/oauth/token`
- Client ID: `invea-tech` (built-in, no configuration needed)
- Credentials: Flowmon username and password

## Configuration

| Parameter | Description |
|---|---|
| Flowmon URL | Base URL of your Flowmon appliance, e.g. `https://flowmon.example.com` |
| Username / Password | Flowmon user credentials |
| Fetch incidents | Enable to pull ADS events automatically as XSIAM alerts |
| Maximum events per fetch | 1–200, default 50 |
| First fetch time | How far back to fetch on first run, e.g. `1 hour`, `2 days` |
| Perspective ID | Optionally limit fetched events to one ADS perspective |

## Commands

### flowmon-ads-perspectives-get

Returns the list of configured ADS detection perspectives.

### flowmon-ads-events-get

Returns ADS anomaly events for a given time range.

| Argument | Description |
|---|---|
| from_time | Start time (`YYYY-MM-DD HH:MM`), default: 1 hour ago |
| to_time | End time (`YYYY-MM-DD HH:MM`), default: now |
| perspective_id | Filter by perspective ID |
| limit | Max events to return (1–200) |

### flowmon-ads-event-get

Returns detailed information about a specific ADS event.

| Argument | Description |
|---|---|
| event_id | ADS event ID (required) |

### flowmon-ads-event-close

Closes or marks an ADS event as false positive, with an optional analyst comment. Also called automatically by the mirroring engine when a XSIAM alert is closed.

| Argument | Description |
|---|---|
| event_id | ADS event ID (required) |
| status | `closed` / `false_positive` / `investigating` (default: `closed`) |
| comment | Optional comment explaining the closure |

## Mirroring

The integration supports **bidirectional mirroring**:

- **XSIAM → Flowmon ADS**: closing a XSIAM alert automatically closes the corresponding ADS event (maps *False Positive* close reason to `false_positive` status).
- **Flowmon ADS → XSIAM**: if an event is closed or marked as false positive in Flowmon ADS, the corresponding XSIAM alert is closed on the next mirror sync.
