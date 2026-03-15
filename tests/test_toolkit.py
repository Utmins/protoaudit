from protoaudit.toolkit.extraction import extract_json_objects
from protoaudit.toolkit.replay import build_replay_plan


def test_extract_json_objects_and_replay_plan():
    raw = 'noise\n{"a":1}\n\n{"b":2}'
    objects = extract_json_objects(raw)
    assert len(objects) == 2

    transcript_json = '[{"send":"hello","recv":"world"}]'
    plan = build_replay_plan(transcript_json)
    assert plan['message_count'] == 1
    assert len(plan['steps']) == 2



def test_parse_transcript_arrow_direction_with_timestamp() -> None:
    from protoaudit.toolkit.transcript import parse_transcript

    parsed = parse_transcript('[00:00:01] C -> S : HELLO\n[00:00:02] S -> C : WORLD')

    assert parsed.entries[0].direction == 'out'
    assert parsed.entries[0].metadata['timestamp'] == '00:00:01'
    assert parsed.entries[1].direction == 'in'
    assert parsed.entries[1].metadata['source'] == 'S'
