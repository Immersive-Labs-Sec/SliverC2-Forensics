# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dns.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tdns.proto\x12\x05\x64nspb\"v\n\nDNSMessage\x12#\n\x04Type\x18\x01 \x01(\x0e\x32\x15.dnspb.DNSMessageType\x12\n\n\x02ID\x18\x02 \x01(\r\x12\r\n\x05Start\x18\x03 \x01(\r\x12\x0c\n\x04Stop\x18\x04 \x01(\r\x12\x0c\n\x04Size\x18\x05 \x01(\r\x12\x0c\n\x04\x44\x61ta\x18\x06 \x01(\x0c*\x87\x01\n\x0e\x44NSMessageType\x12\x07\n\x03NOP\x10\x00\x12\x08\n\x04TOTP\x10\x01\x12\x08\n\x04INIT\x10\x02\x12\x08\n\x04POLL\x10\x03\x12\t\n\x05\x43LOSE\x10\x04\x12\x0c\n\x08MANIFEST\x10\x06\x12\x13\n\x0f\x44\x41TA_TO_IMPLANT\x10\x07\x12\x15\n\x11\x44\x41TA_FROM_IMPLANT\x10\x08\x12\t\n\x05\x43LEAR\x10\tB,Z*github.com/bishopfox/sliver/protobuf/dnspbb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'dns_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z*github.com/bishopfox/sliver/protobuf/dnspb'
  _DNSMESSAGETYPE._serialized_start=141
  _DNSMESSAGETYPE._serialized_end=276
  _DNSMESSAGE._serialized_start=20
  _DNSMESSAGE._serialized_end=138
# @@protoc_insertion_point(module_scope)
