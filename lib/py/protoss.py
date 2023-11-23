#!/usr/bin/env python3

from cffi import FFI
import cosmos.base.v1beta1.coin_pb2
import cosmos.tx.v1beta1.tx_pb2
import cosmos.bank.v1beta1.tx_pb2
import google.protobuf.any_pb2
import json
import urllib.request

def c(x):
    return ffi.new("char[]", x.encode('utf-8'))
def p(x):
    return ffi.string(x).decode('utf-8')

def new_account(prefix):
    sk = ffi.string(C.protoss_cosmos_new_sk())
    address = p(C.protoss_cosmos_sk_address(sk, c(prefix)))
    return (sk, address)

def faucet(origin_phrase, origin_addr_prefix, to_address, amount, denom, chain_id, url, rpc_port="26657"):
    phrase = c(origin_phrase)
    addr_prefix = c(origin_addr_prefix)
    address = p(C.protoss_cosmos_phrase_address(phrase, addr_prefix))
    account_info = get_account_info(address, url)
    tx=ffi.string(C.protoss_cosmos_send_phrase(phrase, int(account_info['sequence']), addr_prefix, c(to_address), c(amount), c(denom), c(chain_id)))
    return json.loads(urllib.request.urlopen(urllib.request.Request(f"{url}:{rpc_port}", data=tx)).read())['result']['hash']

def phrase_address(origin_phrase, origin_addr_prefix):
    phrase = c(origin_phrase)
    addr_prefix = c(origin_addr_prefix)
    return p(C.protoss_cosmos_phrase_address(phrase, addr_prefix))

def get_account_info(address, url, rest_port="1317"):
    return json.loads(urllib.request.urlopen(f"{url}:{rest_port}/cosmos/auth/v1beta1/accounts/{address}").read())['account'] 

def any(type_url, msg):
    return google.protobuf.any_pb2.Any(type_url = type_url, value = msg.SerializeToString())

def tx_body(messages, memo = "nomemo", timeout_height = 4294967295): #4294967295 = MAX_INT32
    return cosmos.tx.v1beta1.tx_pb2.TxBody(messages = messages, memo = memo, timeout_height = timeout_height)

def send(tx, url, rpc_port="26657"):
    return json.loads(urllib.request.urlopen(urllib.request.Request(f"{url}:{rpc_port}", data=tx)).read())['result']['hash']

def tx(sk, tx_body, account_number, account_sequence, fee_amount, fee_denom, chain_id, gas_price = 100000000000):
    return ffi.string(C.protoss_cosmos_tx(sk, int(account_number), int(account_sequence), c(fee_amount), c(fee_denom), gas_price, tx_body.SerializeToString(), c(chain_id)))

## note: passing addr_prefix here could eliminate address
def address_tx(address, sk, tx_body, fee_amount, fee_denom, chain_id, url, rest_port="1317", gas_price = 100000000000):
    account_info = get_account_info(address, url)
    return ffi.string(C.protoss_cosmos_tx(sk, int(account_info['account_number']), int(account_info['sequence']), c(fee_amount), c(fee_denom), gas_price, tx_body.SerializeToString(), c(chain_id)))

def phrase_tx(phrase, addr_prefix, tx_body, fee_amount, fee_denom, chain_id, url, rest_port="1317", gas_price = 100000000000):
    account_info = get_account_info(phrase_address(phrase, addr_prefix), url)
    return ffi.string(C.protoss_cosmos_ptx(phrase, int(account_info['account_number']), int(account_info['sequence']), c(fee_amount), c(fee_denom), gas_price, tx_body.SerializeToString(), c(chain_id)))

def new_funded(funder_phrase, addr_prefix, amount, denom, chain_id, url):
    (sk, sender) = new_account(addr_prefix)
    tx_hash = faucet(funder_phrase, addr_prefix, sender, amount, denom, chain_id, url)
    return f"{sender}#{sk}#{tx_hash}"

def main():
    global C, ffi
    ffi = FFI()
    C = ffi.dlopen("libprotoss.so")
    ffi.cdef("""
        const char * protoss_cosmos_send_phrase(const char *phrase, int nonce, const char *addr_prefix, const char *to_address, const char *amount, const char *denom, const char *chain_id);
        const char * protoss_cosmos_new_sk();
        const char * protoss_cosmos_sk_address(const char *sk, const char *addr_prefix);
        const char * protoss_cosmos_phrase_address(const char *phrase, const char *addr_prefix);
        const char * protoss_cosmos_tx(const char *sk, long account_number, long nonce, const char *fee_amount, const char *fee_denom, long gas, const char *body_bytes, const char *chain_id);
        const char * protoss_cosmos_ptx(const char *phrase, long account_number, long nonce, const char *fee_amount, const char *fee_denom, long gas, const char *body_bytes, const char *chain_id);
        """)

main()