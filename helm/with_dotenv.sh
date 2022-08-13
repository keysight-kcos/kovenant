#!/bin/bash

env $(grep -v '^#' .env | xargs) $@
unset $(grep -v '^#' .env | cut -d = -f 1 | xargs)
