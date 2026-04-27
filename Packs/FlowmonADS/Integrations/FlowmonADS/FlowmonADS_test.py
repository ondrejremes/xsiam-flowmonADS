import pytest
import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import demistomock as demisto
from FlowmonADS import (
    FlowmonClient,
    flowmon_ads_perspectives_get_command,
    flowmon_ads_events_get_command,
    flowmon_ads_event_get_command,
    fetch_incidents,
    test_module,
    _event_to_incident,
)

BASE_URL = 'https://flowmon.example.com'

MOCK_TOKEN_RESPONSE = {
    'access_token': 'test-token-abc123',
    'token_type': 'bearer',
    'expires_in': 604800,
}

MOCK_PERSPECTIVES = [
    {'id': 1, 'name': 'Security issues', 'priorities': []},
    {'id': 2, 'name': 'Operational issues', 'priorities': []},
]

MOCK_EVENTS = [
    {
        'id': 4510401,
        'type': 'ANOMALY',
        'time': '2024-01-15 10:30:00',
        'flowStamp': '2024-01-15 10:30:00',
        'batch': 1705312200,
        'detail': 'Unusual number of services detected on the network.',
        'interest': 0.75,
        'priority': 4,
        'method': 'HEUR_SERVICE_COUNT',
        'nfSource': {'id': 6, 'name': 'LAN/live/router1', 'virtual': 0},
        'perspectives': [{'id': 1, 'name': 'Security issues', 'priority': 4}],
        'source': {'blacklisted': 0, 'country': 'LAN', 'ip': '192.168.1.100', 'resolved': ''},
        'targets': [
            {'blacklisted': 0, 'country': 'LAN', 'ip': '192.168.1.1', 'resolved': ''},
            {'blacklisted': 0, 'country': 'LAN', 'ip': '10.0.0.1', 'resolved': ''},
        ],
        'comments': [],
    },
    {
        'id': 4510402,
        'type': 'ANOMALY',
        'time': '2024-01-15 10:45:00',
        'flowStamp': '2024-01-15 10:45:00',
        'batch': 1705313100,
        'detail': 'Port scan detected from internal host.',
        'interest': 0.90,
        'priority': 5,
        'method': 'HEUR_PORTSCAN',
        'nfSource': {'id': 3, 'name': 'DMZ/live/fw1', 'virtual': 0},
        'perspectives': [{'id': 1, 'name': 'Security issues', 'priority': 5}],
        'source': {'blacklisted': 0, 'country': 'LAN', 'ip': '192.168.2.50', 'resolved': ''},
        'targets': [],
        'comments': [],
    },
]


@pytest.fixture
def mock_client():
    client = FlowmonClient(
        base_url=BASE_URL,
        username='admin',
        password='secret',
        verify=False,
        proxy=False,
    )
    client._token = 'test-token-abc123'
    return client


def test_test_module_success(mock_client):
    mock_client.get_perspectives = MagicMock(return_value=MOCK_PERSPECTIVES)
    result = test_module(mock_client)
    assert result == 'ok'


def test_test_module_auth_failure(mock_client):
    mock_client.test_connectivity = MagicMock(side_effect=Exception('401 Unauthorized'))
    with pytest.raises(Exception, match='401 Unauthorized'):
        test_module(mock_client)


def test_flowmon_ads_perspectives_get_command(mock_client):
    mock_client.get_perspectives = MagicMock(return_value=MOCK_PERSPECTIVES)
    result = flowmon_ads_perspectives_get_command(mock_client, {})
    assert result.outputs_prefix == 'FlowmonADS.Perspective'
    assert len(result.outputs) == 2
    assert result.outputs[0]['ID'] == 1
    assert result.outputs[1]['Name'] == 'Operational issues'


def test_flowmon_ads_events_get_command(mock_client):
    mock_client.get_events = MagicMock(return_value=MOCK_EVENTS)
    args = {
        'from_time': '2024-01-15 10:00',
        'to_time': '2024-01-15 11:00',
        'limit': '50',
    }
    result = flowmon_ads_events_get_command(mock_client, args)
    assert result.outputs_prefix == 'FlowmonADS.Event'
    assert len(result.outputs) == 2
    assert result.outputs[0]['ID'] == 4510401
    assert result.outputs[0]['SourceIP'] == '192.168.1.100'
    assert '192.168.1.1' in result.outputs[0]['TargetIPs']


def test_flowmon_ads_event_get_command(mock_client):
    mock_client.get_event = MagicMock(return_value=MOCK_EVENTS[0])
    result = flowmon_ads_event_get_command(mock_client, {'event_id': '4510401'})
    assert result.outputs['ID'] == 4510401
    assert result.outputs['Priority'] == 4
    assert result.outputs['SourceIP'] == '192.168.1.100'
    assert result.outputs['Method'] == 'HEUR_SERVICE_COUNT'


def test_flowmon_ads_event_get_command_not_found(mock_client):
    mock_client.get_event = MagicMock(return_value={})
    result = flowmon_ads_event_get_command(mock_client, {'event_id': '9999999'})
    assert 'not found' in result.readable_output


def test_event_to_incident_severity_mapping():
    for priority, expected_severity in [(1, 1), (2, 1), (3, 2), (4, 3), (5, 4)]:
        event = dict(MOCK_EVENTS[0])
        event['priority'] = priority
        incident = _event_to_incident(event)
        assert incident['severity'] == expected_severity, \
            f'Priority {priority} should map to severity {expected_severity}'


def test_event_to_incident_structure():
    event = MOCK_EVENTS[0]
    incident = _event_to_incident(event)
    assert incident['name'] == event['detail']
    assert incident['occurred'] == event['time']
    custom = incident['CustomFields']
    assert custom['flowmonadseventid'] == '4510401'
    assert custom['flowmonadssourceip'] == '192.168.1.100'
    assert custom['flowmonadstargetips'] == '192.168.1.1, 10.0.0.1'


def test_fetch_incidents_first_run(mock_client):
    mock_client.get_events = MagicMock(return_value=MOCK_EVENTS)
    params = {'max_fetch': '50', 'first_fetch': '1 hour'}
    next_run, incidents = fetch_incidents(mock_client, {}, params)
    assert len(incidents) == 2
    assert 'last_fetch' in next_run
    assert '4510401' in next_run['last_ids'] or '4510402' in next_run['last_ids']


def test_fetch_incidents_deduplication(mock_client):
    mock_client.get_events = MagicMock(return_value=MOCK_EVENTS)
    last_run = {
        'last_fetch': '2024-01-15 10:00:00',
        'last_ids': ['4510401', '4510402'],
    }
    params = {'max_fetch': '50'}
    next_run, incidents = fetch_incidents(mock_client, last_run, params)
    assert len(incidents) == 0


def test_fetch_incidents_with_perspective_filter(mock_client):
    mock_client.get_events = MagicMock(return_value=[MOCK_EVENTS[0]])
    params = {'max_fetch': '50', 'perspective_id': '1'}
    _, incidents = fetch_incidents(mock_client, {}, params)
    mock_client.get_events.assert_called_once()
    call_kwargs = mock_client.get_events.call_args
    assert call_kwargs.kwargs.get('perspective_id') == '1' or call_kwargs.args[2] == '1'
