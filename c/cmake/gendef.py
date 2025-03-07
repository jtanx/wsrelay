#!/usr/bin/env python3
import base64
import os
import secrets
import sys

TEMPLATE = """#pragma once

#include <stdint.h>

static const uint8_t SRV_SECRET[] = {{
    {srv_secret}
}};
"""


def generate(output: str):
    srv_secret_b32 = os.environ.get("WSRELAY_SRV_SECRET")
    if srv_secret_b32:
        srv_secret = base64.b32decode(srv_secret_b32)
    else:
        srv_secret = secrets.token_bytes(20)

    assert len(srv_secret) == 20, len(srv_secret)
    sec = ", ".join(f"0x{x:02x}" for x in srv_secret)

    with open(output, "w") as fp:
        fp.write(TEMPLATE.format(srv_secret=sec))


if __name__ == "__main__":
    generate(sys.argv[1])
