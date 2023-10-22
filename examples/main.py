#!/usr/bin/env python3

from cffi import FFI

def main():
    ffi = FFI()
    C = ffi.dlopen("libprotoss.so")
    ffi.cdef("""const char * protoss_cosmos_send_phrase(const char *phrase, int nonce, const char *addr_prefix, const char *to_address,const char *amount,const char *denom, int chain_id);""")
    phrase = ffi.new("char[]", b"power forum anger wash problem innocent rifle emerge culture offer among palace essay maid junior spin wife meat six gasp two rough boat marble")
    addr_prefix = ffi.new("char[]", b"cosmos")
    to_address = ffi.new("char[]", b"cosmos...")
    amount = ffi.new("char[]", b"100000")
    denom = ffi.new("char[]", b"atom")
    nonce = 1
    chain_id = 1
    p=C.protoss_cosmos_send_phrase(phrase, nonce, addr_prefix, to_address, amount, denom, chain_id)
    print(ffi.string(p))

main()
