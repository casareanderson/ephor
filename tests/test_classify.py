from ephor import classify


def test_builtin_named_agents():
    assert classify.classify("/usr/bin/ollama serve") == "ollama"
    assert classify.classify("node /opt/cursor-server/bin/x") == "cursor"
    assert classify.classify("/opt/homebrew/bin/aider --model gpt") == "aider"


def test_hermes_profile_capture():
    assert classify.classify("python hermes --profile coder --once") == "hermes:coder"
    assert classify.classify("hermes serve") == "hermes"


def test_python_framework_collapses():
    # framework invoked by name on the command line collapses to the framework label
    assert classify.classify("python3 -m langchain.agents run") == "langchain"
    assert classify.classify("python3 -m crewai run") == "crewai"
    assert classify.classify("python /opt/autogen/chat.py --autogen") == "autogen"
    # a plain user script that merely *imports* a framework keeps its own name (the cmdline can't see imports)
    assert classify.classify("python /srv/bot/my_flow.py") == "py:my_flow"


def test_python_fallback_module_and_file():
    assert classify.classify("python3 -m mypkg.worker") == "py:mypkg"
    assert classify.classify("python /home/x/scrape.py --go") == "py:scrape"
    assert classify.classify("python3", exe="/usr/bin/python3.11") == "py:repl"


def test_node_fallback():
    assert classify.classify("node /srv/app/server.js") == "node:server"
    assert classify.classify("node", exe="/usr/bin/node") == "node"


def test_other_fallback_uses_exe_basename():
    assert classify.classify("", exe="/opt/weird/thing") == "other:thing"
    assert classify.classify("/some/random/binary --flag") == "other:binary"


def test_ignore_defaults():
    assert classify.ignored("/usr/sbin/sshd -D")
    assert classify.ignored("/lib/systemd/systemd-resolved")
    assert classify.ignored("node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js")
    assert not classify.ignored("python3 /srv/agent.py")


def test_user_pattern_wins(monkeypatch):
    # user config patterns take priority over built-ins
    import importlib

    from ephor import config
    monkeypatch.setitem(config.CONF, "agents", [{"pattern": r"my_special_bot", "name": "special"}])
    importlib.reload(classify)
    try:
        assert classify.classify("python3 my_special_bot.py") == "special"
    finally:
        monkeypatch.setitem(config.CONF, "agents", [])
        importlib.reload(classify)
