# Flowmon ADS

Integrates with **Progress Flowmon Anomaly Detection System (ADS)** REST API to ingest network anomaly events as XSIAM alerts and enrich investigations with flow-based threat intelligence.

## What does this pack do?

- Continuously pulls ADS anomaly events into XSIAM as incidents.
- Lets analysts query events, perspectives, and event details directly from XSIAM.
- Maps Flowmon ADS priority levels (1–5) to XSIAM severity levels.

## Use cases

- **Threat detection** — surface network behavior anomalies (port scans, DDoS, data exfiltration, brute force) detected by Flowmon ADS as XSIAM alerts.
- **Incident enrichment** — query Flowmon ADS for event details during investigations.
- **Investigation acceleration** — correlate network anomalies with endpoint and identity events in XSIAM.

## Authentication

The integration authenticates using Flowmon's **OAuth2 Password Grant** flow:

- Token URL: `https://<flowmon-host>/resources/oauth/token`
- Client ID: `invea-tech` (fixed, built-in)
- Credentials: Flowmon username + password

The bearer token is automatically acquired and reused per integration instance.

## Configuration

| Parameter | Description |
|---|---|
| Flowmon URL | Base URL of your Flowmon appliance, e.g. `https://flowmon.example.com` |
| Credentials | Flowmon username and password |
| Fetch incidents | Enable to pull ADS events automatically |
| Maximum events per fetch | Number of events to pull per run (1–200, default 50) |
| First fetch time | How far back to fetch on first run, e.g. `1 hour`, `2 days` |
| Perspective ID | Optionally limit fetched events to a specific perspective |

## Commands

### flowmon-ads-perspectives-get

Returns the list of configured ADS detection perspectives.

### flowmon-ads-events-get

Returns ADS anomaly events for a given time range.

| Argument | Description |
|---|---|
| from_time | Start time (YYYY-MM-DD HH:MM), default: 1 hour ago |
| to_time | End time (YYYY-MM-DD HH:MM), default: now |
| perspective_id | Filter by perspective ID |
| limit | Max events to return (1–200) |

### flowmon-ads-event-get

Returns detailed information about a specific ADS event by ID.

| Argument | Description |
|---|---|
| event_id | ADS event ID (required) |
