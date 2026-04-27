import demistomock as demisto
from CommonServerPython import *
import json

OAUTH_CLIENT_ID = 'invea-tech'
DEFAULT_FETCH_LIMIT = 50
MAX_FETCH_LIMIT = 200

# ADS event priority → XSIAM severity mapping (priority 1=lowest, 5=highest)
PRIORITY_TO_SEVERITY = {
    1: IncidentSeverity.LOW,
    2: IncidentSeverity.LOW,
    3: IncidentSeverity.MEDIUM,
    4: IncidentSeverity.HIGH,
    5: IncidentSeverity.CRITICAL,
}

# ADS event status values used in the API
ADS_STATUS_OPEN = 'open'
ADS_STATUS_CLOSED = 'closed'
ADS_STATUS_FALSE_POSITIVE = 'false_positive'
ADS_STATUS_INVESTIGATING = 'investigating'


class FlowmonClient(BaseClient):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip('/'), verify=verify, proxy=proxy)
        self._username = username
        self._password = password
        self._token: str | None = None

    # ── Authentication ────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        response = self._http_request(
            'POST',
            '/resources/oauth/token',
            data={
                'grant_type': 'password',
                'client_id': OAUTH_CLIENT_ID,
                'username': self._username,
                'password': self._password,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            auth=None,
        )
        token = response.get('access_token')
        if not token:
            raise DemistoException('Flowmon authentication failed: no access_token in response.')
        return token

    def _auth_headers(self) -> dict:
        if not self._token:
            self._token = self._get_token()
        return {'Authorization': f'bearer {self._token}'}

    def _get(self, path: str, params: dict | None = None) -> Any:
        return self._http_request('GET', path, headers=self._auth_headers(), params=params)

    def _put(self, path: str, body: dict) -> Any:
        return self._http_request('PUT', path, headers=self._auth_headers(), json_data=body)

    def _post(self, path: str, body: dict) -> Any:
        return self._http_request('POST', path, headers=self._auth_headers(), json_data=body)

    # ── ADS read endpoints ────────────────────────────────────────────────────

    def get_perspectives(self) -> list:
        return self._get('/rest/ads/perspectives') or []

    def get_events(self, from_time: str, to_time: str, perspective_id: str | None = None,
                   limit: int = DEFAULT_FETCH_LIMIT) -> list:
        search: dict = {'from': from_time, 'to': to_time}
        if perspective_id:
            search['perspective'] = str(perspective_id)
        params = {'search': json.dumps(search)}
        result = self._get('/rest/ads/events', params=params)
        events = result if isinstance(result, list) else []
        return events[:limit]

    def get_event(self, event_id: str | int) -> dict:
        return self._get(f'/rest/ads/event/{event_id}') or {}

    # ── ADS write endpoints ───────────────────────────────────────────────────

    def close_event(self, event_id: str | int, status: str = ADS_STATUS_CLOSED,
                    comment: str | None = None) -> dict:
        """Update ADS event status. Falls back to adding a comment if PUT is unsupported."""
        body: dict = {'status': status}
        if comment:
            body['comment'] = comment
        try:
            return self._put(f'/rest/ads/event/{event_id}', body) or {}
        except Exception as e:
            demisto.debug(f'PUT /rest/ads/event/{event_id} failed ({e}); trying comment fallback')
            if comment:
                self.add_event_comment(event_id, comment)
            raise

    def add_event_comment(self, event_id: str | int, text: str) -> dict:
        """Add a comment to a Flowmon ADS event."""
        return self._post(f'/rest/ads/event/{event_id}/comment', {'text': text}) or {}

    def test_connectivity(self) -> None:
        self._get('/rest/ads/perspectives')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_datetime(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M')


def _parse_event_time(event: dict) -> datetime:
    raw = event.get('time') or event.get('flowStamp', '')
    try:
        return datetime.strptime(raw, '%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return datetime.utcnow()


def _event_to_incident(event: dict) -> dict:
    priority = event.get('priority', 3)
    severity = PRIORITY_TO_SEVERITY.get(priority, IncidentSeverity.MEDIUM)
    source = event.get('source', {})
    targets = event.get('targets', [])
    perspectives = event.get('perspectives', [])
    nf_source = event.get('nfSource', {})
    name = event.get('detail') or f"Flowmon ADS anomaly #{event.get('id')}"

    return {
        'name': name,
        'occurred': event.get('time', ''),
        'rawJSON': json.dumps(event),
        'severity': severity,
        'type': 'Flowmon ADS Event',
        'dbotMirrorId': str(event.get('id', '')),
        'dbotMirrorInstance': demisto.integrationInstance(),
        'dbotMirrorDirection': 'Both',
        'CustomFields': {
            'flowmonadseventid': str(event.get('id', '')),
            'flowmonadseventtype': event.get('type', ''),
            'flowmonadsinterest': event.get('interest'),
            'flowmonadspriority': priority,
            'flowmonadssourceip': source.get('ip', ''),
            'flowmonadsourcecountry': source.get('country', ''),
            'flowmonadstargetips': ', '.join(t.get('ip', '') for t in targets if t.get('ip')),
            'flowmonadsdetectionmodel': event.get('method', ''),
            'flowmonadsnfsource': nf_source.get('name', ''),
            'flowmonadsperspectives': ', '.join(p.get('name', '') for p in perspectives),
        },
    }


def _build_event_output(event: dict) -> dict:
    return {
        'ID': event.get('id'),
        'Type': event.get('type'),
        'Time': event.get('time'),
        'FlowStamp': event.get('flowStamp'),
        'Detail': event.get('detail'),
        'Priority': event.get('priority'),
        'Interest': event.get('interest'),
        'Status': event.get('status'),
        'SourceIP': (event.get('source') or {}).get('ip'),
        'SourceCountry': (event.get('source') or {}).get('country'),
        'SourceBlacklisted': (event.get('source') or {}).get('blacklisted'),
        'TargetIPs': [t.get('ip') for t in (event.get('targets') or []) if t.get('ip')],
        'Perspectives': [p.get('name') for p in (event.get('perspectives') or [])],
        'NFSource': (event.get('nfSource') or {}).get('name'),
        'Method': event.get('method'),
        'Comments': event.get('comments', []),
    }


# ── Command functions ─────────────────────────────────────────────────────────

def test_module(client: FlowmonClient) -> str:
    client.test_connectivity()
    return 'ok'


def flowmon_ads_perspectives_get_command(client: FlowmonClient, args: dict) -> CommandResults:
    perspectives = client.get_perspectives()
    outputs = [{'ID': p.get('id'), 'Name': p.get('name')} for p in perspectives]
    readable = tableToMarkdown('Flowmon ADS Perspectives', outputs,
                               headers=['ID', 'Name'], removeNull=True)
    return CommandResults(
        outputs_prefix='FlowmonADS.Perspective',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=readable,
        raw_response=perspectives,
    )


def flowmon_ads_events_get_command(client: FlowmonClient, args: dict) -> CommandResults:
    from_time = args.get('from_time') or _format_datetime(datetime.utcnow() - timedelta(hours=1))
    to_time = args.get('to_time') or _format_datetime(datetime.utcnow())
    perspective_id = args.get('perspective_id')
    limit = min(arg_to_number(args.get('limit')) or DEFAULT_FETCH_LIMIT, MAX_FETCH_LIMIT)

    events = client.get_events(from_time=from_time, to_time=to_time,
                               perspective_id=perspective_id, limit=limit)
    outputs = [
        {
            'ID': e.get('id'),
            'Type': e.get('type'),
            'Time': e.get('time'),
            'Detail': e.get('detail'),
            'Priority': e.get('priority'),
            'Interest': e.get('interest'),
            'Status': e.get('status'),
            'SourceIP': (e.get('source') or {}).get('ip'),
            'TargetIPs': [t.get('ip') for t in (e.get('targets') or []) if t.get('ip')],
            'Perspectives': [p.get('name') for p in (e.get('perspectives') or [])],
            'NFSource': (e.get('nfSource') or {}).get('name'),
        }
        for e in events
    ]
    readable = tableToMarkdown(
        'Flowmon ADS Events', outputs,
        headers=['ID', 'Type', 'Time', 'Priority', 'Interest', 'SourceIP', 'Detail'],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix='FlowmonADS.Event',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=readable,
        raw_response=events,
    )


def flowmon_ads_event_get_command(client: FlowmonClient, args: dict) -> CommandResults:
    event_id = args['event_id']
    event = client.get_event(event_id)
    if not event:
        return CommandResults(readable_output=f'Event `{event_id}` not found.')

    output = _build_event_output(event)
    readable = tableToMarkdown(f'Flowmon ADS Event {event_id}', [output],
                               headers=['ID', 'Type', 'Time', 'Priority', 'Interest', 'SourceIP', 'Detail'],
                               removeNull=True)
    return CommandResults(
        outputs_prefix='FlowmonADS.Event',
        outputs_key_field='ID',
        outputs=output,
        readable_output=readable,
        raw_response=event,
    )


def flowmon_ads_event_close_command(client: FlowmonClient, args: dict) -> CommandResults:
    event_id = args['event_id']
    status = args.get('status', ADS_STATUS_CLOSED)
    comment = args.get('comment')
    result = client.close_event(event_id, status=status, comment=comment)
    msg = f'Event {event_id} status updated to **{status}**.'
    return CommandResults(readable_output=msg, raw_response=result)


# ── Mirroring ─────────────────────────────────────────────────────────────────

def get_remote_data_command(client: FlowmonClient, args: dict) -> GetRemoteDataResponse:
    parsed = GetRemoteDataArgs(args)
    event_id = parsed.remote_incident_id
    event = client.get_event(event_id)

    mirrored = _build_event_output(event)
    entries: list = []

    # If Flowmon ADS marked the event as closed/false_positive, close the XSIAM alert
    ads_status = event.get('status', '')
    if ads_status in (ADS_STATUS_CLOSED, ADS_STATUS_FALSE_POSITIVE):
        close_reason = 'Resolved' if ads_status == ADS_STATUS_CLOSED else 'False Positive'
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': f'Closing XSIAM alert: Flowmon ADS event status is "{ads_status}".',
            'Note': True,
            'Tags': ['flowmon-mirror-close'],
        })
        mirrored['closeReason'] = close_reason
        mirrored['closeNotes'] = f'Flowmon ADS event {event_id} was marked as {ads_status}.'

    return GetRemoteDataResponse(mirrored_object=mirrored, entries=entries)


def update_remote_system_command(client: FlowmonClient, args: dict) -> str:
    parsed = UpdateRemoteSystemArgs(args)
    event_id = parsed.remote_incident_id

    if not parsed.incident_changed:
        demisto.debug(f'Skipping mirror update for event {event_id}: no changes.')
        return event_id

    # Determine the XSIAM incident status
    xsiam_status = parsed.status
    close_reason = parsed.close_reason or ''
    incident_data = parsed.data or {}

    # Only act on incident closure
    if xsiam_status != IncidentStatus.DONE:
        demisto.debug(f'Skipping mirror update for event {event_id}: status={xsiam_status} is not DONE.')
        return event_id

    # Map XSIAM close reason to ADS status
    if 'false positive' in close_reason.lower():
        ads_status = ADS_STATUS_FALSE_POSITIVE
    else:
        ads_status = ADS_STATUS_CLOSED

    analyst = incident_data.get('owner', '')
    comment_text = f'Closed via Cortex XSIAM'
    if analyst:
        comment_text += f' by {analyst}'
    if close_reason:
        comment_text += f'. Reason: {close_reason}'

    try:
        client.close_event(event_id, status=ads_status, comment=comment_text)
        demisto.debug(f'Flowmon ADS event {event_id} closed with status={ads_status}.')
    except Exception as e:
        demisto.error(f'Failed to close Flowmon ADS event {event_id}: {e}')

    return event_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    mapping = SchemeTypeMapping(type_name='Flowmon ADS Event')
    for field, desc in [
        ('flowmonadseventid', 'Flowmon ADS event ID'),
        ('flowmonadseventtype', 'Event type (e.g. ANOMALY)'),
        ('flowmonadspriority', 'Priority (1–5)'),
        ('flowmonadsinterest', 'Interest score (0–1)'),
        ('flowmonadssourceip', 'Source IP address'),
        ('flowmonadsourcecountry', 'Source country'),
        ('flowmonadstargetips', 'Target IP addresses'),
        ('flowmonadsdetectionmodel', 'Detection model code'),
        ('flowmonadsnfsource', 'NetFlow source name'),
        ('flowmonadsperspectives', 'Perspective names'),
    ]:
        mapping.add_field(field, desc)
    return GetMappingFieldsResponse([mapping])


# ── Fetch incidents ───────────────────────────────────────────────────────────

def fetch_incidents(client: FlowmonClient, last_run: dict, params: dict) -> tuple[dict, list]:
    fetch_limit = min(arg_to_number(params.get('max_fetch')) or DEFAULT_FETCH_LIMIT, MAX_FETCH_LIMIT)
    perspective_id = params.get('perspective_id') or None

    now = datetime.utcnow()
    last_fetch_str = last_run.get('last_fetch')
    if last_fetch_str:
        last_fetch = datetime.strptime(last_fetch_str, '%Y-%m-%d %H:%M:%S')
    else:
        first_fetch_str = params.get('first_fetch') or '1 hour'
        last_fetch = dateparser.parse(f'{first_fetch_str} UTC',
                                      settings={'RETURN_AS_TIMEZONE_AWARE': False}) or (now - timedelta(hours=1))

    from_time = _format_datetime(last_fetch)
    to_time = _format_datetime(now)

    events = client.get_events(from_time=from_time, to_time=to_time,
                               perspective_id=perspective_id, limit=fetch_limit)

    last_ids: set = set(last_run.get('last_ids', []))
    incidents = []
    new_ids: list = []
    latest_time = last_fetch

    for event in events:
        eid = str(event.get('id', ''))
        if eid in last_ids:
            continue
        event_time = _parse_event_time(event)
        if event_time > latest_time:
            latest_time = event_time
        incidents.append(_event_to_incident(event))
        new_ids.append(eid)

    next_run = {
        'last_fetch': _format_datetime(latest_time) if incidents else _format_datetime(now),
        'last_ids': new_ids[-MAX_FETCH_LIMIT:],
    }
    return next_run, incidents


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url', '').rstrip('/')
    credentials = params.get('credentials', {})
    username = credentials.get('identifier', '')
    password = credentials.get('password', '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = FlowmonClient(
        base_url=base_url,
        username=username,
        password=password,
        verify=verify,
        proxy=proxy,
    )

    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, args))
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args))
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
        elif command == 'flowmon-ads-perspectives-get':
            return_results(flowmon_ads_perspectives_get_command(client, args))
        elif command == 'flowmon-ads-events-get':
            return_results(flowmon_ads_events_get_command(client, args))
        elif command == 'flowmon-ads-event-get':
            return_results(flowmon_ads_event_get_command(client, args))
        elif command == 'flowmon-ads-event-close':
            return_results(flowmon_ads_event_close_command(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute command "{command}". Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
