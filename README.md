# protoss
A library to support Ethereum and Cosmos SDK encoding from Rust or languages implementing C FFI

# python protobuf stubs
```shell
protoc -I../../tools/include -I../cosmos-sdk/proto -I../cosmos-proto/proto -I../gogoproto --python_out=lib/py/ gogoproto/gogo.proto cosmos/base/v1beta1/coin.proto cosmos_proto/cosmos.proto cosmos/tx/v1beta1/tx.proto google/protobuf/any.proto cosmos/crypto/multisig/v1beta1/multisig.proto cosmos/tx/signing/v1beta1/signing.proto cosmos/bank/v1beta1/tx.proto cosmos/bank/v1beta1/bank.proto cosmos/msg/v1/msg.proto
```

# bank send example
```shell
export LD_LIBRARY_PATH=target/debug; export PYTHONPATH=lib/py; export FUNDER_PHRASE="***"; export PYTHONPYCACHEPREFIX=.cache; python3 examples/bank_send.py
```