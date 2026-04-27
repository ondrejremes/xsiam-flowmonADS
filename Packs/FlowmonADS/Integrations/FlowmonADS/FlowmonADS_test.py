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
    flowmon_ads_event_close_command,
    get_remote_data_command,
    update_remote_system_command,
    fetch_incidents,
    test_module,
    _event_to_incident,
    ADS_STATUS_CLOSED,
    ADS_STATUS_FALSE_POSITIVE,
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


def test_flowmon_ads_event_close_command(mock_client):
    mock_client.close_event = MagicMock(return_value={})
    result = flowmon_ads_event_close_command(mock_client, {'event_id': '4510401', 'status': 'closed'})
    mock_client.close_event.assert_called_once_with('4510401', status='closed', comment=None)
    assert '4510401' in result.readable_output
    assert 'closed' in result.readable_output


def test_flowmon_ads_event_close_with_comment(mock_client):
    mock_client.close_event = MagicMock(return_value={})
    flowmon_ads_event_close_command(
        mock_client,
        {'event_id': '4510401', 'status': 'false_positive', 'comment': 'Lab traffic, not a threat'}
    )
    mock_client.close_event.assert_called_once_with(
        '4510401', status='false_positive', comment='Lab traffic, not a threat'
    )


def test_get_remote_data_open_event(mock_client):
    open_event = dict(MOCK_EVENTS[0])
    open_event['status'] = 'open'
    mock_client.get_event = MagicMock(return_value=open_event)

    args = {'id': '4510401', 'lastUpdate': '2024-01-15T00:00:00Z'}
    response = get_remote_data_command(mock_client, args)

    assert response.mirrored_object['ID'] == 4510401
    assert len(response.entries) == 0


def test_get_remote_data_closed_event_triggers_xsiam_close(mock_client):
    closed_event = dict(MOCK_EVENTS[0])
    closed_event['status'] = 'closed'
    mock_client.get_event = MagicMock(return_value=closed_event)

    args = {'id': '4510401', 'lastUpdate': '2024-01-15T00:00:00Z'}
    response = get_remote_data_command(mock_client, args)

    assert response.mirrored_object.get('closeReason') == 'Resolved'
    assert len(response.entries) == 1
    assert 'closed' in response.entries[0]['Contents'].lower()


def test_get_remote_data_false_positive_event(mock_client):
    fp_event = dict(MOCK_EVENTS[0])
    fp_event['status'] = 'false_positive'
    mock_client.get_event = MagicMock(return_value=fp_event)

    args = {'id': '4510401', 'lastUpdate': '2024-01-15T00:00:00Z'}
    response = get_remote_data_command(mock_client, args)

    assert response.mirrored_object.get('closeReason') == 'False Positive'


def test_update_remote_system_closes_event_on_xsiam_close(mock_client):
    mock_client.close_event = MagicMock(return_value={})

    args = {
        'remote_incident_id': '4510401',
        'incident_changed': True,
        'status': 2,  # IncidentStatus.DONE
        'close_reason': 'Resolved',
        'data': json.dumps({'owner': 'analyst1', 'CustomFields': {'flowmonadseventid': '4510401'}}),
        'entries': '[]',
    }
    result = update_remote_system_command(mock_client, args)

    mock_client.close_event.assert_called_once()
    call_args = mock_client.close_event.call_args
    assert call_args.kwargs.get('status') == ADS_STATUS_CLOSED or call_args.args[1] == ADS_STATUS_CLOSED
    assert result == '4510401'


def test_update_remote_system_false_positive_reason(mock_client):
    mock_client.close_event = MagicMock(return_value={})

    args = {
        'remote_incident_id': '4510402',
        'incident_changed': True,
        'status': 2,
        'close_reason': 'False Positive',
        'data': json.dumps({'owner': ''}),
        'entries': '[]',
    }
    update_remote_system_command(mock_client, args)

    call_args = mock_client.close_event.call_args
    used_status = call_args.kwargs.get('status') or call_args.args[1]
    assert used_status == ADS_STATUS_FALSE_POSITIVE


def test_update_remote_system_skips_when_not_closed(mock_client):
    mock_client.close_event = MagicMock()

    args = {
        'remote_incident_id': '4510401',
        'incident_changed': True,
        'status': 1,  # Active, not done
        'close_reason': '',
        'data': '{}',
        'entries': '[]',
    }
    update_remote_system_command(mock_client, args)
    mock_client.close_event.assert_not_called()


def test_update_remote_system_skips_when_no_change(mock_client):
    mock_client.close_event = MagicMock()

    args = {
        'remote_incident_id': '4510401',
        'incident_changed': False,
        'status': 2,
        'close_reason': 'Resolved',
        'data': '{}',
        'entries': '[]',
    }
    update_remote_system_command(mock_client, args)
    mock_client.close_event.assert_not_called()


def test_fetch_incident_has_mirror_fields():
    event = MOCK_EVENTS[0]
    incident = _event_to_incident(event)
    assert incident.get('dbotMirrorId') == '4510401'
    assert incident.get('dbotMirrorDirection') == 'Both'
    assert 'dbotMirrorInstance' in incident
