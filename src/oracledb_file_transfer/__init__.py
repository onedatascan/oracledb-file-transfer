import smart_open
import smart_open.transport
import smart_open.s3

from . import oracledirectory
from .oracledirectory import RAW_MAX_BYTES as CHUNK_SIZE

smart_open.transport.register_transport(oracledirectory)

builtin_open = open
open = smart_open.open
parse_uri = smart_open.parse_uri
s3_iter_bucket = smart_open.s3.iter_bucket
register_compressor = smart_open.register_compressor
patch_pathlib = smart_open.smart_open_lib.patch_pathlib


__all__ = [
    "builtin_open",
    "open",
    "parse_uri",
    "s3_iter_bucket",
    "register_compressor",
    "patch_pathlib",
    "CHUNK_SIZE",
]


def lambda_handler(event, context):
    from oracledb_file_transfer.entrypoints.aws_lambda import lambda_handler as handler

    return handler(event, context)
