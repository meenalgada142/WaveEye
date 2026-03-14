AXI_LITE_RULE_DB = {
    "RULE_5": {
        "title": "Write response must follow address/data handshake",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.4.3 Write Response Channel",
        "requirement": "Slave must issue BVALID only after both AW and W handshakes complete.",
    },
    "RULE_6": {
        "title": "BVALID must remain asserted until BREADY",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.2 Channel Handshake",
        "requirement": "VALID must remain asserted until READY is observed.",
    },
    "RULE_10": {
        "title": "Read response must follow AR handshake",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.4.2 Read Data Channel",
        "requirement": "Slave must assert RVALID only after ARVALID/ARREADY handshake.",
    },
    "RULE_11": {
        "title": "Read/Write response must not be combinationally withdrawn",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.2 Channel Handshake",
        "requirement": "Once VALID is asserted it must remain until handshake completes.",
    },
    "RULE_12": {
        "title": "No second read address while prior read response is outstanding",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.4.1 Read Address Channel / single outstanding transaction model",
        "requirement": "Do not accept/issue a new AR transaction before the previous read response completes.",
    },
    "RULE_13": {
        "title": "Write response must be produced after accepted write transaction",
        "amba_spec": "AMBA AXI4-Lite Specification",
        "section": "A3.4.3 Write Response Channel",
        "requirement": "After AW+W are accepted, the slave must produce BVALID and complete the B channel handshake.",
    },
}
