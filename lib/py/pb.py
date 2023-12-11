#!/usr/bin/env python3

import google.protobuf.any_pb2
import cosmos.tx.v1beta1.tx_pb2
   
def any(type_url, msg):
    return google.protobuf.any_pb2.Any(type_url = type_url, value = msg.SerializeToString())

def tx_body(messages, memo = "nomemo", timeout_height = 4294967295): #4294967295 = MAX_INT32
    return cosmos.tx.v1beta1.tx_pb2.TxBody(messages = messages, memo = memo, timeout_height = timeout_height).SerializeToString()
