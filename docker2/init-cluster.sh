#!/bin/bash
 docker run --rm \
  -e "DATABASE_URL=postgres://hydra:hydra@192.168.0.3:5432/hydra?sslmode=disable" \
  -e "SYSTEM_SECRET=y82XL-wAPCCZu+B4" \
  -v $(pwd)/hydra_init:/src \
  --entrypoint /bin/sh \
  -it oryd/hydra:latest
