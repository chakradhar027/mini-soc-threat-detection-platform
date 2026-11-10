# Infrastructure & Container Orchestration

## Overview

This directory contains the container orchestration specifications, environment configurations, and persistent volume definitions for the Mini SOC and Threat Detection Platform.

## Networking Plan

Three dedicated Docker bridge networks isolate the workloads:
1. `soc-honeynet` (`172.28.10.0/24`) - Untrusted honeypot DMZ.
2. `soc-iot-net` (`172.28.20.0/24`) - Isolated IoT sensor network.
3. `soc-mgmt-net` (`172.28.30.0/24`) - SOC management core (Wazuh, PostgreSQL, Backend API, Frontend).

## Volume Persistence Structure

Log outputs and database records persist on the host under:
```
infrastructure/docker/volumes/
├── cowrie/
│   ├── log/
│   └── tty/
├── dionaea/
│   ├── log/
│   └── binaries/
├── mosquitto/
│   ├── log/
│   └── data/
├── postgres/
│   └── data/
└── wazuh/
    ├── manager/
    ├── indexer/
    └── dashboard/
```

*Note: All honeypot log volumes are mounted as read-only (`:ro`) into the log ingestion service to prevent tampering.*

