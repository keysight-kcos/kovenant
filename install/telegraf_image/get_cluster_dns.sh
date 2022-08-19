#!/bin/bash

output=$(kubectl cluster-info)

[[ $output =~ ^.*https://([[:digit:]]*\.[[:digit:]]*\.[[:digit:]]*\.[[:digit:]]):.*$ ]]
echo ${BASH_REMATCH[1]}
