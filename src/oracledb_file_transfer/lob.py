import io
import logging
from codecs import iterdecode
from typing import IO, Generic, Iterable, Iterator, Tuple, Type, TypeVar, Union, cast

import oracledb
from typing_extensions import Literal

# oracledb package has some issues with its __init__.py
# pyright: reportPrivateImportUsage=false
DB_LOB = oracledb.LOB
DB_CLOB = oracledb.CLOB
ContentType = Union[Type[str], Type[bytes]]
IOMode = Literal["r", "w"]
SupportedOpenModes = Literal["r", "w", "rt", "wt", "rb", "wb"]

EMPTY_BYTE: bytes = b""
EMPTY_STR: str = ""
LOB_FETCH_SIZE_MULT: int = 8

_T = TypeVar("_T", str, bytes)

logger = logging.getLogger(__name__)


class LobStreamer(Generic[_T]):
    def __init__(self, lob: DB_LOB):
        self._lob = lob
        self._content_type: Union[Type[str], Type[bytes]] = (
            str if self._lob.type in ("DB_TYPE_CLOB", "CLOB") else bytes
        )
        self._default_fetch_size = lob.getchunksize() * LOB_FETCH_SIZE_MULT
        self._empty = (
            EMPTY_STR if self._content_type is str else EMPTY_BYTE
        )
        self._pos = 1
        self._complete = False

    def read(self, size: int = -1) -> Union[_T, None]:
        if size == -1:
            data = self._empty

            while not self._complete:
                chunk = self._fetch(self._default_fetch_size)

                if chunk is not None and isinstance(chunk, self._content_type):
                    data += chunk  # type: ignore
            return data  # type: ignore
        else:
            return self._fetch(size)

    def _fetch(self, size: int) -> Union[_T, None]:
        if self._complete:
            return None

        chunk = self._lob.read(self._pos, size)

        if len(chunk) < size:
            self._complete = True

        self._pos += len(chunk)
        return chunk  # type: ignore


class LobReader(io.RawIOBase):
    def __init__(self, lob: DB_CLOB) -> None:
        self._stream = LobStreamer[bytes](lob)

    def read(self, size: int = -1) -> Union[bytes, None]:
        return self._stream.read(size)

    def readall(self):
        return self._stream.read()

    def readinto(self, buf: bytearray) -> int:
        buf_size = len(buf)
        mv_buf = memoryview(buf)
        data = self.read()
        if data and len(data) > 0:
            mv_buf[: len(data)] = data
            return len(buf) - buf_size
        else:
            return 0

    def readable(self) -> bool:
        return True


class OracleLOBWrapper(IO):
    """
    Provides a file-like interface for Oracle LOB. Callers should use the open
    classmethod
    """

    chunk_size_mult = 8

    def __init__(self):
        self._pos = 1

        # Set by open()
        self._lob: DB_LOB
        self._content_type: ContentType
        self._io_mode: IOMode
        self._encoding: Union[str, None]
        self._default_chunk_size: int
        self._chunk_size: int
        self._raw_stream: Union[Iterator[bytes], None] = None
        self._decoded_stream: Union[Iterator[str], None] = None

    def _stream_chunks(self, chunk_size: Union[int, None] = None) -> Iterator[bytes]:
        if chunk_size and chunk_size > 0:
            init_chunk_size = chunk_size
        else:
            init_chunk_size = self._default_chunk_size

        self._chunk_size = init_chunk_size
        while True:
            chunk_size = self._chunk_size
            data = cast(bytes, self._lob.read(self._pos, chunk_size))
            if data:
                yield data
            if len(data) < chunk_size:
                break
            self._pos += len(data)

    def _stream_decode(self, stream: Iterable[bytes], encoding: str) -> Iterator[str]:
        yield from iterdecode(stream, encoding)

    @property
    def content_type(self) -> ContentType:
        return self._content_type

    @classmethod
    def open(
        cls,
        lob: DB_LOB,
        mode: SupportedOpenModes = "r",
        encoding: Union[str, None] = None,
    ) -> IO:
        instance = cls()
        instance._lob = lob
        instance._content_type, instance._io_mode = parse_open_mode(mode)
        instance._encoding = encoding
        instance._default_chunk_size = lob.getchunksize() * cls.chunk_size_mult
        instance._chunk_size = instance._default_chunk_size
        return instance

    def __enter__(self):
        return self

    def __exit__(self, exc_ty, exec_val, tb) -> None:
        if self._io_mode == "w" and self._lob.isopen():
            self._lob.close()

    def read(self, size: int = -1) -> Union[str, bytes, None]:
        if not self._raw_stream:
            self._raw_stream = self._stream_chunks(size)

        if not self._decoded_stream and self._encoding:
            self._decoded_stream = self._stream_decode(self._raw_stream, self._encoding)

        if self._decoded_stream and self._encoding:
            if size == -1:
                data = str()
                for chunk in self._decoded_stream:
                    data += chunk
                return data
            else:
                next(self._decoded_stream)
        else:
            if size == -1:
                data = bytes() if self.content_type == bytes else str()
                for chunk in self._raw_stream:
                    data += chunk  # type: ignore
                    return data
            else:
                self._chunk_size = size
                return next(self._raw_stream)

    def readline(self) -> Union[str, bytes, None]:
        raise NotImplementedError()

    def write(self, data) -> None:
        raise NotImplementedError()

    def seek(self, position):
        raise NotImplementedError()

    def tell(self) -> int:
        return self._pos



def parse_open_mode(
    mode: SupportedOpenModes,
) -> Tuple[ContentType, IOMode]:
    content_type: ContentType = str
    if "b" in mode:
        content_type = bytes
        if "t" in mode:
            raise io.UnsupportedOperation("Conflicting io modes %s", mode)

    io_mode: IOMode = "r"
    if "w" in mode:
        io_mode = "w"
        if "r" in mode:
            raise io.UnsupportedOperation("Read/write mode not supported %s", mode)

    return content_type, io_mode
