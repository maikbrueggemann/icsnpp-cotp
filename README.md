# ICSNPP-COTP

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Connection-Oriented Transport Protocol (COTP)

## Overview

This plugin provides a protocol analyzer for the OSI Connection-Oriented Transport Protocol (COTP) (ISO 8073
/ X.224) for use within Zeek.

## Dependencies

COTP is dependent on [TPKT](https://github.com/DINA-community/icsnpp-tpkt),
which must also be installed.
In addition, zeek must support spicy.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).

```bash
zkg refresh
zkg install cotp
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_COTP` under the list of plugins.

If users have ZKG configured to load packages (see `@load packages` in the( [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.)

## Logging

One dataset is logged for each cotp connection containing the following fields. 

| Field             | Type      | Description                                                       |
| ----------------- |-----------|-------------------------------------------------------------------|
| ts_start          | time      | Timestamp of the first pdu                                        |
| ts_end            | time      | Timestamp of the last pdu                                         |
| uid               | string    | Unique ID for this connection                                     |
| orig_h            | address   | Source IP address                                                 |
| orig_p            | port      | Source port                                                       |
| resp_h            | address   | Destination IP address                                            |
| resp_p            | port      | Destination port                                                  |
| calling_tsap      | string    | Calling transport service access point (tsap)                     |
| called_tsap       | string    | Called transport service access point (tsap)                      |
| class             | count     | Class                                                             |
| has_connect       | bool      | True if the connection request pdu was seen else false            |
| has_disconnect    | bool      | True if the disconnect request pdu was seen else false            |
| data_pkts         | count     | Total number of pdus                                              |
| data_bytes        | count     | Total number of payload bytes                                     |
| error             | bool      | True if an error pdu was received else false                      |
| reject_cause      | bool      | cause if the error; only valid if error is true                   |

## Limitations

Payload extraction is only supported for class 0. Higher layers are therefore only called when class 0 is used.

## License

The software was developed on behalf of the BSI (Federal Office for Information Security)

Copyright (c) 2025-2026 by DINA-Community BSD 3-Clause. [See License](/COPYING)
