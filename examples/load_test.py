#!/usr/bin/env python3

import load
import protoss
import cosmos.base.v1beta1.coin_pb2
import cosmos.bank.v1beta1.tx_pb2
import time
import os
import sys

def main():

    url = "http://"+os.getenv("CHAIN_HOST")
    chain_id = os.getenv("CHAIN_ID")
    addr_prefix = os.getenv("ADDR_PREFIX")
    denom= os.getenv("DENOM")
    funder_phrase = os.getenv("FUNDER_PHRASE")
    funder_address = protoss.phrase_address(funder_phrase, addr_prefix)

    (sk, sender) = protoss.new_account(addr_prefix)
    
    tx_hash = protoss.faucet(funder_phrase, addr_prefix, sender, "1000000000", denom, chain_id, url)
    print(tx_hash, file=sys.stderr)
    
    time.sleep(5)

    msg = cosmos.bank.v1beta1.tx_pb2.MsgSend(
        from_address = sender,
        to_address = funder_address,
        amount = [cosmos.base.v1beta1.coin_pb2.Coin(
            amount = "100000",
            denom=denom
        )]
    )

    tx_body = protoss.tx_body([
        protoss.any("/cosmos.bank.v1beta1.MsgSend", msg)
        ])

    account_info = protoss.get_account_info(sender, url)

    l = lambda nonce:load.send(protoss.tx(sk, tx_body, account_info['account_number'], nonce, "100000", denom, chain_id))
    load.cycle(int(account_info['sequence']), l)


main()