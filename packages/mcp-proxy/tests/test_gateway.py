import pytest

from notary_mcp_proxy import Gateway


def test_stubs_raise() -> None:
    gateway = Gateway(())
    with pytest.raises(NotImplementedError):
        gateway.check_pins("t", "h")
    with pytest.raises(NotImplementedError):
        gateway.label_result("t", "raw")
