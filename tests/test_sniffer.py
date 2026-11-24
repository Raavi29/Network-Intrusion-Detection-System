import pytest

from src.packet_sniffer import ScapyPacketSource


def test_live_capture_fails_fast_when_it_cannot_start():
    # Regression: a capture that failed in scapy's background thread went unnoticed,
    # and the pipeline sat idle until shutdown.
    source = ScapyPacketSource("no-such-interface0", None, 1600, False)
    with pytest.raises(RuntimeError, match="capture"):
        source.start(lambda pkt: None)
    source.stop()  # stopping a failed source must not raise
