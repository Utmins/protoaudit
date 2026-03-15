from protoaudit.cli import build_parser


def test_cli_parser_builds():
    parser = build_parser()
    assert parser.prog == "protoaudit"



def test_cli_has_plugins_command():
    parser = build_parser()
    args = parser.parse_args(["plugins", "list"])
    assert args.command == "plugins"
    assert args.plugins_command == "list"
