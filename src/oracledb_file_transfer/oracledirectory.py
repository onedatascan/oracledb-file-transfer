"""Implements reading and writing to/from Oracle Database directories."""

import collections
import io
import logging
import os.path
import urllib.parse
from typing import IO, Any, Callable, Dict, Tuple, Union, cast

try:
    import oracledb
except ImportError:
    MISSING_DEPS = True
    oracledb = None

import smart_open.utils

assert oracledb

Kwargs = Dict[str, Any]
# oracledb package has some issues with its __init__.py
# pyright: reportPrivateImportUsage=false
Connection = oracledb.Connection
DatabaseError = oracledb.DatabaseError
DB_OBJECT_TYPE = oracledb.ObjectType
DB_OBJECT = oracledb.OBJECT


RAW_MAX_BYTES: int = 32767
DEFAULT_PORT: int = 1521
NO_DATA_FOUND = "01403"

SQL_GET_DIRECTORY_PATH = """
    select directory_path
    from all_directories
    where directory_name = upper(:dir_name)
"""

SQL_GET_DIRECTORY_FROM_PATH = """
    select directory_name
    from all_directories
    where rtrim(directory_path, '/') = :dir_path
"""

REQUIRED_CONNECTION_PARAMS = ["user", "password", "host", "port", "database"]

SCHEMES: Tuple[str, ...] = ("oracledirectory",)
URI_EXAMPLES: Tuple[str, ...] = (
    "oracledirectory://DATA_PUMP_DIR/foo.dmp",
    "oracledirectory:///opt/oracle/oradata/admin/ORCLCDB/dpdump/foo.dmp",
    "oracledirectory://username:password@host:port/database?file=/opt/oracle/oradata/foo.dmp",
    "oracledirectory://username:password@host:port/database?dir=DATA_PUMP_DIR&file=foo.dmp",
)

logger = logging.getLogger(__name__)

Uri = collections.namedtuple(
    "Uri",
    [
        "scheme",
        "user",
        "password",
        "host",
        "port",
        "database",
        "path",
        "ora_directory",
    ],
)


def parse_uri(uri_as_string: str) -> Uri:
    split_uri = urllib.parse.urlsplit(uri_as_string)
    assert split_uri.scheme in SCHEMES

    if split_uri.query:
        params = dict(
            map(
                lambda x: x.split("="), urllib.parse.unquote(split_uri.query).split("&")
            )
        )

        if "file" not in params:
            raise ValueError("Invalid oracledirectory URI: file parameter not found!")

        path = params["file"]

        if "dir" in params:
            ora_directory = params["dir"]
        else:
            ora_directory = None

        user = split_uri.username
        password = split_uri.password
        host = split_uri.hostname
        database = split_uri.path.lstrip("/")
        port = split_uri.port or DEFAULT_PORT
    else:
        user, password, host, database, port = None, None, None, None, None
        ora_directory = split_uri.netloc

        if ora_directory:
            path = split_uri.path.lstrip("/")
        else:
            path, ora_directory = split_uri.path, None

    return Uri(
        scheme=split_uri.scheme,
        user=user,
        password=password,
        host=host,
        database=database,
        port=port,
        path=path,
        ora_directory=ora_directory,
    )


def open_uri(uri: str, mode: str, transport_params: Kwargs) -> IO[bytes]:
    smart_open.utils.check_kwargs(open, transport_params)
    parsed_uri: Uri = parse_uri(uri)
    logger.debug("Parsed URI: %s", parsed_uri)

    if "connection" in transport_params:
        return open(
            parsed_uri.path,
            mode,
            ora_directory=parsed_uri.ora_directory,
            connection=transport_params["connection"],
        )

    user = transport_params.get("user", parsed_uri.user)
    password = transport_params.get("password", parsed_uri.password)
    host = transport_params.get("host", parsed_uri.host)
    database = transport_params.get("database", parsed_uri.database)
    port = transport_params.get("port", parsed_uri.port)

    return open(
        parsed_uri.path,
        mode,
        ora_directory=parsed_uri.ora_directory,
        user=user,
        password=password,
        host=host,
        database=database,
        port=port,
    )


def open(
    path: str,
    mode: str,
    ora_directory: Union[str, None] = None,
    connection: Union[Connection, None] = None,
    user: Union[str, None] = None,
    password: Union[str, None] = None,
    host: Union[str, None] = None,
    port: Union[int, None] = None,
    database: Union[str, None] = None,
) -> IO[bytes]:
    ...

    if connection:
        connection = connection
    elif user and password and host and port and database:
        connection = oracledb.connect(
            user=user, password=password, host=host, port=port, service_name=database
        )
    else:
        raise ValueError(
            f"Supply a connection argument or all required connection params: {REQUIRED_CONNECTION_PARAMS}"
        )

    if not ora_directory:
        dir_path = os.path.split(path)[0]
        ora_directory = OracleDirectoryHandler.get_dir_from_path(dir_path, connection)

    file_handler = OracleFileHandler(path, ora_directory, connection, mode)

    if "r" in mode and "w" in mode:
        raise io.UnsupportedOperation("Read/write mode not supported %s", mode)
    elif "r" in mode:
        return OracleFileReader(file_handler)
    elif "w" in mode:
        return OracleFileWriter(file_handler)
    else:
        raise io.UnsupportedOperation(mode)


def requires_file_handle(read: bool = True, write: bool = False):
    def decorator(_method: Callable):
        def wrapper(self, *args, **kwargs):
            if self.file_handle is None:
                raise ValueError(
                    "Method %s() requires file handle!"
                    "Call get_file_handle() first." % _method.__name__
                )

            if read and write:
                pass
            elif read and "r" not in self.mode:
                raise ValueError(
                    "Method %s() requires file open mode 'r'" % _method.__name__
                )
            elif write and "w" not in self.mode:
                raise ValueError(
                    "Method %s() requires file open mode 'w'" % _method.__name__
                )
            return _method(self, *args, **kwargs)

        return wrapper

    return decorator


def object_loads(obj: oracledb.Object) -> Union[dict, list, None]:  # type: ignore
    """Loads an Oracle object type into a dict or list"""
    if obj.type.iscollection:
        retval = []
        for value in obj.aslist():
            if isinstance(value, oracledb.Object):
                value = object_loads(value)
            retval.append(value.lower() if isinstance(value, str) else value)
    else:
        retval = {}
        for attr in obj.type.attributes:
            value = getattr(obj, attr.name)
            if value is None:
                continue
            if isinstance(value, oracledb.Object):
                value = object_loads(value)
            retval[attr.name.lower()] = value
    return retval


class OracleDirectoryHandler:
    def __init__(
        self,
        ora_directory: str,
        connection: Connection,
    ):
        self.connection = connection
        self.ora_directory = ora_directory.upper()
        self._dir_path: Union[str, None] = None

    @classmethod
    def get_dir_from_path(
        cls,
        path: str,
        connection: Connection,
    ) -> str:

        logger.debug("Resolving directory from path: %s", str(path))
        with connection.cursor() as cursor:
            cursor.execute(
                SQL_GET_DIRECTORY_FROM_PATH, parameters={"dir_path": str(path)}
            )
            result = iter(cursor.fetchall())

            try:
                dir_rec = next(result)
                dir_name = dir_rec[0]
                logger.debug("Found directory %s", dir_name)
            except (StopIteration, IndexError):
                raise ValueError(f"Oracle directory not found! {str(path)}")

            return dir_name

    @property
    def path(self) -> str:
        if self._dir_path is not None:
            return self._dir_path
        with self.connection.cursor() as cursor:
            cursor.execute(
                SQL_GET_DIRECTORY_PATH,
                parameters={"dir_name": str(self.ora_directory)},
            )
            result = iter(cursor.fetchall())

            try:
                dir_rec = next(result)
                self._dir_path = dir_rec[0]
            except (StopIteration, IndexError):
                raise ValueError(
                    "Oracle directory not found! %s",
                    self.ora_directory,
                )
            return self._dir_path


class OracleFileHandler:
    def __init__(
        self,
        file_name: str,
        ora_directory: str,
        connection: Connection,
        mode: Union[str, None] = None,
    ):
        self.connection = connection

        self.ora_directory = ora_directory
        self._directory_handler = OracleDirectoryHandler(ora_directory, self.connection)
        self.file_name = file_name

        if mode:
            self.get_file_handle(mode)
        else:
            self.mode = None
            self.file_handle = None

    @property
    def path(self) -> str:
        return os.path.join(self._directory_handler.path, self.file_name)

    # TODO: consider caching
    @property
    def file_exists(self) -> bool:
        return self.get_attrs()[0]

    # TODO: consider caching
    @property
    def file_length(self) -> int:
        return self.get_attrs()[1]

    # TODO: consider caching
    @property
    def block_size(self) -> int:
        return self.get_attrs()[2]

    def get_file_handle(self, mode: str) -> DB_OBJECT:
        file_type: DB_OBJECT_TYPE = self.connection.gettype("UTL_FILE.FILE_TYPE")

        try:
            with self.connection.cursor() as cursor:
                self.mode = mode
                self.file_handle = cursor.callfunc(
                    name="UTL_FILE.FOPEN",
                    return_type=file_type,
                    keyword_parameters=dict(
                        location=self.ora_directory,
                        filename=self.file_name,
                        open_mode=self.mode,
                        max_linesize=RAW_MAX_BYTES,
                    ),
                )
        except DatabaseError as exc:
            raise DatabaseError(
                f"File error: {self.ora_directory}/{self.file_name}"
            ) from exc

    def get_attrs(self):
        with self.connection.cursor() as cursor:
            file_exists = cursor.var(bool)
            file_length = cursor.var(int)
            block_size = cursor.var(int)
            cursor.callproc(
                name="UTL_FILE.FGETATTR",
                keyword_parameters=dict(
                    location=self.ora_directory,
                    filename=self.file_name,
                    fexists=file_exists,
                    file_length=file_length,
                    block_size=block_size,
                ),
            )
            return (
                cast(bool, file_exists.getvalue()),
                cast(int, file_length.getvalue()),
                cast(int, block_size.getvalue()),
            )

    def get_info(self) -> Tuple[dict, int]:
        if not self.file_name.endswith(".dmp"):
            raise Exception("get_info() is only valid for dumpfiles!")

        info_obj_typ: DB_OBJECT_TYPE = self.connection.gettype("SYS.KU$_DUMPFILE_INFO")
        with self.connection.cursor() as cursor:
            info_obj = cursor.var(info_obj_typ)
            dmp_file_type = cursor.var(int)
            cursor.callproc(
                name="dbms_datapump.get_dumpfile_info",
                keyword_parameters={
                    "filename": self.file_name,
                    "directory": self.ora_directory,
                    "info_table": info_obj,
                    "filetype": dmp_file_type,
                },
            )
            dmp_file_type = cast(int, dmp_file_type.getvalue())
            info_data = cast(dict, object_loads(info_obj.getvalue()))  # type: ignore
            logger.debug(info_data)

        return info_data, dmp_file_type

    @requires_file_handle(read=True, write=False)
    def read(self, size=RAW_MAX_BYTES) -> bytes:
        if size > RAW_MAX_BYTES:
            raise ValueError("Cannot request more than %d at a time", RAW_MAX_BYTES)
        with self.connection.cursor() as cursor:
            buf = cursor.var(bytes, size=RAW_MAX_BYTES)
            try:
                cursor.callproc(
                    name="UTL_FILE.GET_RAW",
                    keyword_parameters=dict(
                        file=self.file_handle, buffer=buf, len=size
                    ),
                )
            except DatabaseError as e:
                (error,) = e.args
                if error.code == NO_DATA_FOUND:
                    return b""
                else:
                    raise e
            data = buf.getvalue()
            if data is None:
                data = b""
            return cast(bytes, data)

    @requires_file_handle(read=False, write=True)
    def write(self, chunk: bytes) -> int:
        if len(chunk) > RAW_MAX_BYTES:
            raise ValueError(
                f"Cannot write more than %d bytes in a single call {RAW_MAX_BYTES}",
            )
        with self.connection.cursor() as cursor:
            cursor.callproc(
                name="UTL_FILE.PUT_RAW",
                keyword_parameters=dict(
                    file=self.file_handle, buffer=chunk, autoflush=True
                ),
            )
            return len(chunk)

    def is_open(self) -> bool:
        with self.connection.cursor() as cursor:
            return cast(
                bool,
                cursor.callfunc(
                    name="UTL_FILE.IS_OPEN",
                    return_type=bool,
                    keyword_parameters=dict(file=self.file_handle),
                ),
            )

    def delete(self) -> int:
        self.get_attrs()
        if self.file_exists:
            with self.connection.cursor() as cursor:
                try:
                    cursor.callproc(
                        name="UTL_FILE.FREMOVE",
                        keyword_parameters=dict(
                            location=self.ora_directory, filename=self.file_name
                        ),
                    )
                except DatabaseError:
                    return 1
        return 0

    @requires_file_handle(read=True, write=True)
    def close(self) -> None:
        with self.connection.cursor() as cursor:
            if self.is_open():
                cursor.callproc(
                    name="UTL_FILE.FCLOSE",
                    keyword_parameters=dict(file=self.file_handle),
                )


class OracleFileReader(io.BufferedIOBase, IO[bytes]):
    def __init__(self, file_handler: OracleFileHandler):
        self._file_handler = file_handler
        self._buffer = bytearray()
        self._pos = 0
        self._eof = False
        self._line_terminator = b"\n"

    def read(self, size=-1) -> bytes:
        if size == 0:
            return b""
        if size < 0:
            while not self._eof:
                self._read_to_buffer()
            return self._consume_from_buffer(len(self._buffer))
        if self._eof:
            if len(self._buffer) == 0:
                return b""
            else:
                return self._consume_from_buffer(size)
        else:
            while not self._eof and len(self._buffer) < size + self._pos:
                self._read_to_buffer()
            return self._consume_from_buffer(size)

    def read1(self, size=-1) -> bytes:
        return self.read(size)

    def readinto(self, buf: Union[bytearray, memoryview]) -> int:
        data = self.read(len(buf))
        if not data:
            return 0
        buf[: len(data)] = data
        return len(data)

    def readinto1(self, buf: Union[bytearray, memoryview]) -> int:
        return self.readinto(buf)

    def readline(self, limit=-1) -> bytes:
        if limit != -1:
            raise NotImplementedError("limit parameter not implemented!")

        term_pos = self._search_buffer(self._line_terminator)
        while not term_pos and not self._eof:
            self._read_to_buffer()
            term_pos = self._search_buffer(self._line_terminator)

        if term_pos is not None:
            size = term_pos + 1
        else:
            size = -1

        return self._consume_from_buffer(size)

    __closed = False

    def close(self):
        if not self.__closed:
            try:
                logger.debug("Closing %s", self._file_handler.file_name)
                if self._file_handler.is_open:
                    self._file_handler.close()

                del self._buffer
            finally:
                self.__closed = True

    def __del__(self):
        logger.debug("Destructing %s file stream", self._file_handler.file_name)
        try:
            self.close()
        except Exception as e:
            logger.warning(
                "Unable to close file %s. Caught: %s", self._file_handler.file_name, e
            )

    def seekable(self) -> bool:
        return False

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def _search_buffer(self, val: bytes) -> Union[int, None]:
        try:
            return self._buffer.index(val)
        except ValueError:
            return None

    def _consume_from_buffer(self, size=-1) -> bytes:
        if size == -1:
            chunk = slice(0, None)
        else:
            chunk = slice(self._pos, min(self._pos + size, len(self._buffer)))
        try:
            return self._buffer[chunk]
        finally:
            del self._buffer[chunk]

    def _read_to_buffer(self, size: int = RAW_MAX_BYTES) -> None:
        if not self._eof:
            data = self._file_handler.read(size)
            if len(data) < size:
                self._eof = True
            self._buffer += data


class OracleFileWriter(io.BufferedIOBase, IO[bytes]):
    MAX_BUFFER = 1024 * 1024

    def __init__(self, file_handler: OracleFileHandler):
        self._file_handler = file_handler
        self._bytes_written = 0

    def write(self, buf: bytes) -> int:
        bufmv = memoryview(buf)

        for i in range(-(len(bufmv) // -RAW_MAX_BYTES)):
            chunk = slice(
                i * RAW_MAX_BYTES,
                min(len(bufmv), (i + 1) * RAW_MAX_BYTES),
            )
            logger.debug(
                "Writing %d bytes to %s",
                len(bufmv[chunk]),
                self._file_handler.file_name,
            )
            self._file_handler.write(bufmv[chunk].tobytes())
            self._bytes_written += len(bufmv[chunk])

        return len(buf)

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return True

    __closed = False

    def close(self) -> None:
        logger.debug("close() called %s", self._file_handler.file_name)
        if not self.__closed:
            try:
                logger.debug("Closing %s", self._file_handler.file_name)
                self.flush()

                if self._file_handler.is_open:
                    self._file_handler.close()
            finally:
                self.__closed = True

    def __del__(self) -> None:
        logger.debug("Destructing %s file stream", self._file_handler.file_name)
        try:
            self.close()
        except Exception as e:
            logger.warning(
                "Unable to close file %s. Caught: %s", self._file_handler.file_name, e
            )

    def tell(self):
        return self._bytes_written

    def detach(self):
        raise io.UnsupportedOperation("detach() not supported")
