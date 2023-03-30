import collections
import logging
import os
from dataclasses import dataclass

import oracledb
import pytest

from oracledb_file_transfer import open

logger = logging.getLogger(__name__)

SCHEME = "oracledirectory"

DB_USER = "system"
DB_PASS = "manager"
DB_HOST = "localhost"
DB_PORT = 1521
DB_NAME = "ORCLCDB"
ORA_DIR = "DATA_PUMP_DIR"
ORA_PATH = "/opt/oracle/admin/ORCLCDB/dpdump"

TEXT_FILE = "crime-and-punishment.txt"
GZIP_FILE = "1984.txt.gz"

CWD = os.path.dirname(os.path.abspath(__file__))
TEST_DATA_DIR = "test_data"

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


@dataclass
class DbParams:
    username: str
    password: str
    host: str
    port: int
    database: str

    @property
    def as_connection(self) -> str:
        return (
            f"{self.username}/{self.password}@{self.host}:{self.port}/{self.database}"
        )

    @property
    def as_uri(self) -> str:
        return (
            f"{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        )


DB_PARAMS = DbParams(
    username=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT, database=DB_NAME
)


def get_expect_data(test_file_path: str, mode, **kwargs):
    with open(test_file_path, mode, **kwargs) as fin:
        data = fin.read()
    return data


def extract_filename(path: str):
    return os.path.split(path)[-1]


@pytest.fixture(scope="module", autouse=True)
def connection():
    return oracledb.connect(DB_PARAMS.as_connection)


@pytest.fixture
def text_file(connection):
    path = os.path.join(CWD, TEST_DATA_DIR, TEXT_FILE)
    yield path
    from oracledb_file_transfer.oracledirectory import OracleFileHandler

    fh = OracleFileHandler(
        file_name=TEXT_FILE, ora_directory=ORA_DIR, connection=connection, mode="w"
    )
    fh.delete()


@pytest.fixture
def gzip_file(connection):
    path = os.path.join(CWD, TEST_DATA_DIR, GZIP_FILE)
    yield path
    from oracledb_file_transfer.oracledirectory import OracleFileHandler

    fh = OracleFileHandler(
        file_name=GZIP_FILE, ora_directory=ORA_DIR, connection=connection, mode="w"
    )
    fh.delete()


@pytest.mark.parametrize(
    "scenario",
    [
        dict(
            name="named_directory",
            uri=f"{SCHEME}://{ORA_DIR}/{TEXT_FILE}",
            expect_uri=Uri(
                scheme=SCHEME,
                user=None,
                password=None,
                host=None,
                port=None,
                database=None,
                path=TEXT_FILE,
                ora_directory=ORA_DIR,
            ),
        ),
        dict(
            name="path_to_directory",
            uri=f"{SCHEME}://{ORA_PATH}/{TEXT_FILE}",
            expect_uri=Uri(
                scheme=SCHEME,
                user=None,
                password=None,
                host=None,
                port=None,
                database=None,
                path=f"{ORA_PATH}/{TEXT_FILE}",
                ora_directory=None,
            ),
        ),
        dict(
            name="connection_with_named_directory",
            uri=f"{SCHEME}://{DB_PARAMS.as_uri}?dir={ORA_DIR}&file={TEXT_FILE}",
            expect_uri=Uri(
                scheme=SCHEME,
                user=DB_PARAMS.username,
                password=DB_PARAMS.password,
                host=DB_PARAMS.host,
                port=DB_PARAMS.port,
                database=DB_PARAMS.database,
                path=TEXT_FILE,
                ora_directory=ORA_DIR,
            ),
        ),
        dict(
            name="connection_with_path_to_directory",
            uri=f"{SCHEME}://{DB_PARAMS.as_uri}?file={ORA_PATH}/{TEXT_FILE}",
            expect_uri=Uri(
                scheme=SCHEME,
                user=DB_PARAMS.username,
                password=DB_PARAMS.password,
                host=DB_PARAMS.host,
                port=DB_PARAMS.port,
                database=DB_PARAMS.database,
                path=f"{ORA_PATH}/{TEXT_FILE}",
                ora_directory=None,
            ),
        ),
        dict(
            name="connection_no_creds_with_path_to_directory",
            uri=f"{SCHEME}://{DB_PARAMS.host}/{DB_PARAMS.database}?file={ORA_PATH}/{TEXT_FILE}",
            expect_uri=Uri(
                scheme=SCHEME,
                user=None,
                password=None,
                host=DB_PARAMS.host,
                port=DB_PARAMS.port,
                database=DB_PARAMS.database,
                path=f"{ORA_PATH}/{TEXT_FILE}",
                ora_directory=None,
            ),
        ),
    ],
)
def test_parse_uri(scenario: dict):
    from oracledb_file_transfer.oracledirectory import parse_uri

    logger.info("Running test_parse_uri for scenario: %s", scenario["name"])

    assert scenario["expect_uri"] == parse_uri(scenario["uri"])


def test_text_copy_named_dir_needs_connection(text_file, connection):
    uri = f"{SCHEME}://{ORA_DIR}/{extract_filename(text_file)}"

    with open(text_file, mode="r") as fin:
        tp = dict(connection=connection)
        with open(uri, mode="w", transport_params=tp) as fout:
            fout.write(fin.read())

        with open(uri, mode="r", transport_params=tp) as fin:
            data = fin.read()

    assert get_expect_data(text_file, mode="r") == data


def test_text_copy_path_dir_needs_connection(text_file, connection):
    uri = f"{SCHEME}://{ORA_PATH}/{extract_filename(text_file)}"

    with open(text_file, mode="r") as fin:
        tp = dict(connection=connection)
        with open(uri, mode="w", transport_params=tp) as fout:
            fout.write(fin.read())

        with open(uri, mode="r", transport_params=tp) as fin:
            data = fin.read()

    assert get_expect_data(text_file, mode="r") == data


def test_text_copy_named_dir(text_file):
    uri = f"{SCHEME}://{DB_PARAMS.as_uri}?dir={ORA_DIR}&file={extract_filename(text_file)}"

    with open(text_file, mode="r") as fin:
        with open(uri, mode="w") as fout:
            fout.write(fin.read())

        with open(uri, mode="r") as fin:
            data = fin.read()

    assert get_expect_data(text_file, mode="r") == data


def test_text_copy_path_dir(text_file):
    uri = f"{SCHEME}://{DB_PARAMS.as_uri}?file={ORA_PATH}/{extract_filename(text_file)}"

    with open(text_file, mode="r") as fin:
        with open(uri, mode="w") as fout:
            fout.write(fin.read())

        with open(uri, mode="r") as fin:
            data = fin.read()

    assert get_expect_data(text_file, mode="r") == data


def test_text_copy_path_dir_needs_creds(text_file):
    uri = f"{SCHEME}://{DB_PARAMS.host}/{DB_PARAMS.database}?file={ORA_PATH}/{extract_filename(text_file)}"

    with open(text_file, mode="r") as fin:
        tp = {"user": DB_PARAMS.username, "password": DB_PARAMS.password}
        with open(uri, mode="w", transport_params=tp) as fout:
            fout.write(fin.read())

        with open(uri, mode="r", transport_params=tp) as fin:
            data = fin.read()

    assert get_expect_data(text_file, mode="r") == data


def test_gzip_copy(gzip_file):
    uri = f"{SCHEME}://{DB_PARAMS.as_uri}?dir={ORA_DIR}&file={extract_filename(gzip_file)}"

    with open(gzip_file, mode="r") as fin:
        with open(uri, mode="w") as fout:
            fout.write(fin.read())

        with open(uri, mode="r") as fin:
            data = fin.read()

    assert get_expect_data(gzip_file, mode="r") == data


def test_gzip_copy_no_decompress(gzip_file):
    uri = f"{SCHEME}://{DB_PARAMS.as_uri}?dir={ORA_DIR}&file={extract_filename(gzip_file)}"

    with open(gzip_file, mode="rb", compression="disable") as fin:
        with open(uri, mode="wb") as fout:
            fout.write(fin.read())

        with open(uri, mode="rb", compression="disable") as fin:
            data = fin.read()

    assert get_expect_data(gzip_file, mode="rb", compression="disable") == data
