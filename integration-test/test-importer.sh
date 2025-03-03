#!/usr/bin/env bash
set -e

/modality-reflector import --ingest-protocol-parent-url ${INGEST_PROTOCOL_PARENT_URL} barectf /effective_config.yaml /ctf_stream
/modality workspace sync-indices
/conform spec eval --file /barectf.speqtr --dry-run
