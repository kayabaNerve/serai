#!/bin/bash

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

bitcoind -txindex -regtest \
  -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS \
  -rpcbind=127.0.0.1 -rpcbind=$(hostname) -rpcallowip=0.0.0.0/0
