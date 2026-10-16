def test_public_names_import() -> None:
    from notary_mcp_proxy import Gateway, ToolBackend, ToolPin

    assert (Gateway.__name__, ToolPin.__name__, ToolBackend.__name__) == (
        "Gateway",
        "ToolPin",
        "ToolBackend",
    )
