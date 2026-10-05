import socket

import mdns


def test_service_infos_only_for_listening_known_services():
    infos = mdns.service_infos("diskstation", "192.168.1.191", {"ssh": 22, "http": 80, "ftp": 21, "smb": 0})
    by_type = {i.type: i for i in infos}
    assert set(by_type) == {"_ssh._tcp.local.", "_http._tcp.local."}
    ssh = by_type["_ssh._tcp.local."]
    assert ssh.name == "diskstation._ssh._tcp.local."
    assert ssh.server == "diskstation.local."
    assert ssh.port == 22 and ssh.addresses == [socket.inet_aton("192.168.1.191")]
