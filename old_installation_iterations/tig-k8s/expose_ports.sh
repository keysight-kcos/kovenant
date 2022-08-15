#!/bin/bash

kubectl port-forward --address 0.0.0.0 service/tetragon-tig-service 8086 3000
