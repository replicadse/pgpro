#!/bin/bash

key=b324431d7b22f480d35d09a99610d60c39739204
./target/debug/pgpro decrypt \
    -p=<(printf test) \
    -m=<(./target/debug/pgpro encrypt -p=<(printf test) -m=<(cat ./LICENSE) -k=$key) \
    -k=$key
