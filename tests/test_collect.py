from ephor import collect

# Real-shape `ss -tnpiH state established` output: socket line then an indented info line.
SS = """\
ESTAB 0 0 10.0.0.5:51000 93.184.216.34:443 users:(("python3",pid=4242,fd=7))
	 cubic wscale:7,7 rto:204 bytes_sent:900 bytes_received:204800 segs_out:12
ESTAB 0 0 10.0.0.5:51002 192.168.0.10:5432 users:(("python3",pid=4242,fd=9))
	 cubic bytes_received:10
ESTAB 0 0 10.0.0.5:51004 140.82.121.4:443 users:(("node",pid=5555,fd=3))
	 cubic bytes_received:1048576
ESTAB 0 0 [::1]:8080 [2606:4700:4700::1111]:443 users:(("curl",pid=6001,fd=4))
	 cubic bytes_received:512
"""


def test_parse_ss_attributes_pid_and_bytes():
    conns = collect.parse_ss(SS)
    by_pid = {(c.pid, c.rip): c for c in conns}
    assert (4242, "93.184.216.34") in by_pid
    assert by_pid[(4242, "93.184.216.34")].bytes_recv == 204800
    assert by_pid[(4242, "93.184.216.34")].rport == 443


def test_parse_ss_drops_private_destinations():
    conns = collect.parse_ss(SS)
    rips = {c.rip for c in conns}
    assert "192.168.0.10" not in rips  # private/LAN dropped
    assert "93.184.216.34" in rips


def test_parse_ss_captures_download_size():
    conns = collect.parse_ss(SS)
    node = [c for c in conns if c.pid == 5555][0]
    assert node.bytes_recv == 1048576  # a real 1 MB download, not a ping


def test_parse_ss_ipv6_global():
    conns = collect.parse_ss(SS)
    assert any(c.rip == "2606:4700:4700::1111" for c in conns)


def test_is_internet():
    assert collect.is_internet("8.8.8.8")
    assert not collect.is_internet("192.168.1.1")
    assert not collect.is_internet("127.0.0.1")
    assert not collect.is_internet("10.0.0.1")
    assert not collect.is_internet("not-an-ip")


def test_container_of():
    assert collect.container_of(1, "0::/docker/abc123def4567890") == "abc123def456"
    assert collect.container_of(1, "0::/lxc.payload.100/ns") == "lxc:100"
    assert collect.container_of(1, "0::/init.scope") == ""
