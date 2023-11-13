#!/usr/bin/env python3

import protoss
import cosmos.base.v1beta1.coin_pb2
import cosmos.bank.v1beta1.tx_pb2
import time
import os

def main():

    url = "http://localhost"
    chain_id = "cosmoshub-1"
    addr_prefix = "cosmos"
    funder_phrase = os.getenv("FUNDER_PHRASE")

    (sk, sender) = protoss.new_account(addr_prefix)
    
    tx_hash = protoss.faucet(funder_phrase, addr_prefix, sender, "1000000000", "atom", chain_id, url)
    print(tx_hash)
    
    time.sleep(5)

    msg = cosmos.bank.v1beta1.tx_pb2.MsgSend(
        from_address = sender,
        to_address = "cosmos...",
        amount = [cosmos.base.v1beta1.coin_pb2.Coin(
            amount = "100000",
            denom="atom"
        )]
    )

    tx_body = protoss.tx_body([
        protoss.any("/cosmos.bank.v1beta1.MsgSend", msg)
        ])

    account_info = protoss.get_account_info(sender, url)

    tx_hash = protoss.send(protoss.tx(sk, tx_body, account_info['account_number'], account_info['sequence'], "100000", "atom", chain_id), url)
    print(tx_hash)


main()