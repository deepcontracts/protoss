#!/usr/bin/env python3

from cffi import FFI
import json
import urllib.request

def uuid4():
    return ffi.string(C.protoss_uuid4())

class Signer():
    def __init__(self, secret):
        if self.__class__ == Signer:
            raise Exception('I am abstract!')
        self.secret = secret

class SkSigner(Signer):
    pass

class PhraseSigner(Signer):
    pass  

def c(x):
    return ffi.new("char[]", x.encode('utf-8'))
def p(x):
    return ffi.string(x).decode('utf-8')

def new_account(prefix):
    sk = ffi.string(C.protoss_cosmos_new_sk())
    address = p(C.protoss_cosmos_sk_address(sk, c(prefix)))
    return {'signer': SkSigner(sk), 'address': address}

def phrase_account(phrase, prefix):
    address = phrase_address(phrase, prefix)
    return {'signer': PhraseSigner(phrase), 'address': address}

def sk_address(sk, addr_prefix):
    return p(C.protoss_cosmos_sk_address(sk, c(addr_prefix)))

def phrase_address(phrase, addr_prefix):
    return p(C.protoss_cosmos_phrase_address(c(phrase), c(addr_prefix)))

def get_account_info(address, url, rest_port="1317"):
    j = json.loads(urllib.request.urlopen(f"{url}:{rest_port}/cosmos/auth/v1beta1/accounts/{address}").read())['account']
    return {k: int(v) for k, v in j.items() if k in ['account_number', 'sequence']}

def has_account_info(args):
    return type(args.get('account_number')) is int and type(args.get('sequence')) is int

def sign_tx(tx, s):
    sequence = s['sequence']
    if isinstance(s['signer'], SkSigner):
        return (ffi.string(C.protoss_cosmos_tx(s['signer'].secret, s['account_number'], s['sequence'], c(s['fee_amount']), c(s['denom']), s['gas_price'], tx, c(s['chain_id']))), s | {'sequence': sequence+1})
    elif isinstance(s['signer'], PhraseSigner):
        return (ffi.string(C.protoss_cosmos_ptx(c(s['signer'].secret), s['account_number'], s['sequence'], c(s['fee_amount']), c(s['denom']), s['gas_price'], tx, c(s['chain_id']))), s | {'sequence': sequence+1})
    else:
        return None

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
        const char * protoss_uuid4();
        """)

main()
