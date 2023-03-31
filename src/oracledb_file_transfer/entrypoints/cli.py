import argparse
import logging
import os
import sys

from oracledb_file_transfer import open


logger = logging.getLogger(__name__)


def main() -> int:
    """CLI wrapper for oracledb-file-transfer package"""

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
    )

    if sys.version_info < (3, 7):
        raise RuntimeError("Requires python>=3.7.0")

    parser = argparse.ArgumentParser(description="Remote Oracle Directory file copy")
    parser.add_argument("from_uri", nargs=1)
    parser.add_argument("to_uri", nargs=1)
    parser.add_argument("--decompress", action="store_true", default=False)
    copy_mode = parser.add_mutually_exclusive_group()
    copy_mode.add_argument("--binary", action="store_true")
    copy_mode.add_argument("--text", action="store_true")

    args = parser.parse_args()

    if args.binary:
        read_mode = "rb"
        write_mode = "wb"
    else:
        read_mode = "r"
        write_mode = "w"

    if args.decompress:
        compression_opt = "infer_from_extension"
    else:
        compression_opt = "disable"

    try:
        with open(args.from_uri[0], mode=read_mode, compression=compression_opt) as fin:
            with open(args.to_uri[0], mode=write_mode, compression="disable") as fout:
                fout.write(fin.read())
    except Exception as e:
        print(e, file=sys.stderr)
        return 1
    else:
        return 0
