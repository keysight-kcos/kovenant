#!/bin/bash

helm list --all-namespaces | awk 'NR==2, NR==length() { print $1" "$(NF-1)} '
