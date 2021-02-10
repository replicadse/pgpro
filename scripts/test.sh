#!/bin/bash

key=3ec1ee6e720583c0fb3cf00b370fb074c777eb04
./target/debug/pgpro decrypt \
    -p=<(printf test) \
    -m=<(./target/debug/pgpro encrypt -m=<(cat ./LICENSE) -k=$key) \
    -k=$key
