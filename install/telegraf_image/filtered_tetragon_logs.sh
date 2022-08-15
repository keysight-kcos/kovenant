#!/bin/bash

kubectl logs -n kube-system ds/tetragon -c export-stdout --tail 0 -f | log_filter.py
