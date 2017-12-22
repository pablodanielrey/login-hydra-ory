#!/bin/bash
 docker run --rm \
  -e "DATABASE_URL=postgres://hydra:hydra@192.168.0.3:5432/hydra?sslmode=disable" \
  -e "SYSTEM_SECRET=y82XL-wAPCCZu+B4" \
  --entrypoint /bin/sh \
  -it oryd/hydra:latest

# y se ejecuta a mano ahi adentro.
#  migrate sql $DATABASE_URL
