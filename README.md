# oracledb-file-transfer
oracledb-file-transfer is a Python package that implements the Python [IO](https://docs.python.org/3/library/io.html) interface for [Oracle Directories](https://docs.oracle.com/en/database/oracle/oracle-database/21/adlob/directory-objectshtml#GUID-F7440C27-C7F0-4874-8C3C-F3BC1534CBE0). It provides an `open()` function that allows reading and writing files remotely to and from Oracle Directories. This package extends the [smart-open](https://github.com/RaRe-Technologies/smart_open/blob/develop/howto.md) package which means that you can also use all of its functionality as well with the `open()` function. To work with the smart-open package the `open()` function expects a URI for the file argument. The following URI formats can be used for Oracle Directories:
```
oracledirectory://DATA_PUMP_DIR/foo.dmp
oracledirectory:///opt/oracle/oradata/admin/ORCLCDB/dpdump/foo.dmp
oracledirectory://username:password@host:port/database?dir=DATA_PUMP_DIR&file=foo.dmp
oracledirectory://username:password@host:port/database?file=/opt/oracle/oradata/foo.dmp
```

if a URI format is used that does not include all of the database connection parameters an `oracledb.Connection` can be passed as a `transport_params` argument or any of the required connection args can be passed.


## Package Usage
### Copy a local file

* Providing credentials in the URI
```python
from oracledb_file_transfer import open

dest_uri = "oracledirectory://system:manager@somehost/orclpdb1?dir=DATA_PUMP_DIR&file=foo.dmp"

with open("foo.dmp", mode="r") as fin:
    with open(dest_uri, mode="w") as fout:
        fout.write(fin.read())
```

* Providing an `oracledb.Connection` as transport_param
```python
import oracledb
from oracledb_file_transfer import open

connection = oracledb.connect("system/manager@somehost/orclpdb1")
dest_uri = "oracledirectory://DATA_PUMP_DIR/foo.dmp"

with open("foo.dmp", mode="r") as fin:
    with open(dest_uri, mode="w", transport_params={"connection": connection}) as fout:
        fout.write(fin.read())
```

* Providing connection args as transport_params
```python
from oracledb_file_transfer import open

connection_args = {
    "user": "system",
    "password": "manager",
    "host": "somehost",
    "database": "orclpdb1"
}
dest_uri = "oracledirectory://DATA_PUMP_DIR/foo.dmp"

with open("foo.dmp", mode="r") as fin:
    with open(dest_uri, mode="w", transport_params=connection_args) as fout:
        fout.write(fin.read())
```

### Copy to local
```python
from oracledb_file_transfer import open

src_uri = "oracledirectory://system:manager@somehost/orclpdb1?dir=DATA_PUMP_DIR&file=some-logfile.log"

with open(src_uri, mode="r") as fin:
    with open("some-logfile.log", mode="w") as fout:
        fout.write(fin.read())
```


### Copy a file from S3
```python
from oracledb_file_transfer import open

src_uri = "s3://some-bucket/some-key/foo.dmp"
dest_uri = "oracledirectory://system:manager@somehost/orclpdb1?dir=DATA_PUMP_DIR&file=foo.dmp"

with open(src_uri, mode="r") as fin:
    with open(dest_uri, mode="w") as fout:
        fout.write(fin.read())
```

## CLI Usage
```
oracledb-file-transfer --help
usage: oracledb-file-transfer [-h] [--decompress] [--binary | --text] from_uri to_uri

Remote Oracle Directory file copy

positional arguments:
  from_uri
  to_uri

options:
  -h, --help    show this help message and exit
  --decompress
  --binary
  --text
```

### Copy a file
```
oracledb-file-transfer --binary foo.dmp 'oracledirectory://system:manager@localhost/orclpdb1?dir=DATA_PUMP_DIR&file=foo.dmp'
```

### Copy a file using Docker container
```
docker run --rm -v $PWD:/tmp oracledb-file-transfer --binary /tmp/foo.dmp 'oracledirectory://system:manager@host.docker.internal/orclpdb1?dir=DATA_PUMP_DIR&file=foo.dmp
```