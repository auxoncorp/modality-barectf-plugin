#!/usr/bin/env bash

set -e

/modality wait-until 'shutdown @ default aggregate count() > 0'
/modality workspace sync-indices
/conform spec eval --file /barectf.speqtr --dry-run
