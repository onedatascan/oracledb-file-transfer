from __future__ import annotations

import base64
import functools
import json
import logging.config
import os
import urllib.parse
from http import HTTPStatus
from time import perf_counter
from typing import Final, Protocol, TypeAlias, TypedDict, runtime_checkable

from aws_lambda_powertools import Logger
from aws_lambda_powertools.logging.utils import copy_config_to_registered_loggers
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.parser import (
    BaseModel,
    ValidationError,
    event_parser,
    models,
    parse,
    root_validator,
    validator,
)
from aws_lambda_powertools.utilities.parser.pydantic import (
    AnyUrl,
    Extra,
    Json,
    parse_obj_as,
)
from aws_lambda_powertools.utilities.typing import LambdaContext

import oracledb_file_transfer

# This is done to ensure DEBUG logging from imported modules does not dump secrets to
# the log stream.
logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": bool(os.getenv("DISABLE_EXISTING_LOGGERS", True)),
    }
)
logger = Logger(service="oracledb-file-transfer", level=os.getenv("LOG_LEVEL", "INFO"))
copy_config_to_registered_loggers(logger)

ENVELOPE: Final[str | None] = os.getenv("ENVELOPE")
MEGABYTE: Final[int] = 1024 * 1024
DEFAULT_CHUNK_SIZE: Final[int] = int(
    os.getenv("DEFAULT_CHUNK_SIZE", MEGABYTE)
)
RESOLVE_SECRETS: Final[bool] = bool(os.getenv("RESOLVE_SECRETS", True))

json_types: TypeAlias = str | int | dict | list | bool | float | None
json_str: TypeAlias = str

HTTPResponse = TypedDict(
    "HTTPResponse",
    {
        "isBase64Encoded": bool,
        "statusCode": HTTPStatus,
        "statusDescription": str,
        "headers": dict[str, str],
        "body": json_str,
    },
)


def build_response(
    http_status: HTTPStatus, body: dict[str, json_types]
) -> HTTPResponse:
    response: HTTPResponse = {
        "isBase64Encoded": False,
        "statusCode": http_status,
        "statusDescription": f"{http_status.value} {http_status.phrase}",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
    logger.info("Response: %s", response)
    return response


@runtime_checkable
class HTTPException(Protocol):
    http_status: HTTPStatus


class BadRequest(Exception):
    http_status = HTTPStatus.BAD_REQUEST


class Panic(Exception):
    http_status = HTTPStatus.INTERNAL_SERVER_ERROR


def exception_handler(ex: Exception, extra: dict[str, json_types] | None = None):
    logger.exception(ex, extra=extra)
    if isinstance(ex, HTTPException):
        return build_response(ex.http_status, {"exception": str(ex), "extra": extra})
    else:
        return build_response(
            HTTPStatus.INTERNAL_SERVER_ERROR, {"exception": str(ex), "extra": extra}
        )


class Uri(AnyUrl):
    ...


class RequestModel(BaseModel):
    source_secret: str | None
    destination_secret: str | None
    source_uri: Uri
    destination_uri: Uri
    compression_opt: str | None

    @validator("source_uri", pre=True)
    def inject_source_secret(cls, v, values):
        if "source_secret" in values:
            if RESOLVE_SECRETS:
                secret = values["source_secret"]
                try:
                    return uri_secret_injector(v, secret)
                except Exception as e:
                    raise ValueError(
                        f"Failed to fetch or parse secret: {secret} "
                        f"reason: {str(e)}"
                    ) from e
            else:
                logger.warning(
                    "A secret parameter was received but secret resolution is disabled"
                )
        return v

    @validator("destination_uri", pre=True)
    def inject_destination_secret(cls, v, values):
        if "destination_secret" in values:
            if RESOLVE_SECRETS:
                secret = values["destination_secret"]
                try:
                    return uri_secret_injector(v, secret)
                except Exception as e:
                    raise ValueError(
                        f"Failed to fetch or parse secret: {secret}" f"reason: {str(e)}"
                    ) from e
            else:
                logger.warning(
                    "A secret parameter was received but secret resolution is disabled"
                )
        return v


class Envelope(BaseModel, extra=Extra.allow):
    body: Json[RequestModel]
    isBase64Encoded: bool

    @root_validator(pre=True)
    def prepare_data(cls, values):
        if values.get("isBase64Encoded"):
            encoded = values.get("body")
            logger.debug("Decoding base64 request body before parsing")
            payload = base64.b64decode(encoded).decode("utf-8")
            values["body"] = json.loads(json.dumps(payload))
        return values


def copy(
    source: Uri, destination: Uri, compression_opt: str | None = None
) -> tuple[int, float]:
    start = perf_counter()
    bytes_copied = 0

    if "oracledirectory" in [source.scheme, destination.scheme]:
        chunk_size = oracledb_file_transfer.CHUNK_SIZE
    else:
        chunk_size = DEFAULT_CHUNK_SIZE

    if compression_opt:
        open_read = functools.partial(
            oracledb_file_transfer.open, mode="rb", compression=compression_opt
        )
    else:
        open_read = functools.partial(oracledb_file_transfer.open, mode="rb")

    with open_read(uri=str(source)) as f_in:
        with oracledb_file_transfer.open(str(destination), mode="wb") as f_out:
            while chunk := f_in.read(chunk_size):
                f_out.write(chunk)
                bytes_copied += len(chunk)
                if bytes_copied % (MEGABYTE * 100) == 0:
                    logger.info("Copied %dMB so far", float(bytes_copied) / MEGABYTE)

    took = perf_counter() - start
    return bytes_copied, took


def uri_secret_injector(uri: str, secret: str | None) -> str:
    """
    Overrides or sets any fields in the URI with fields found
    in the provided secret. Secret should be of the form:
        {
            "username": "system",
            "password": "manager",
            "hostname": "host1",    // optional
            "database": "orclpdb1", // optional
            "port": 1521            // optional
        }
    Some of these fields are specific to certain URI types and
    will only be applied if the URI scheme is applicable.

    For an oracledirectory scheme, the URI should be of the form:
        oracledirectory://DATA_PUMP_DIR/foo.dmp
        oracledirectory:///opt/oracle/oradata/admin/ORCLCDB/dpdump/foo.dmp
    """

    def get_secret_value(secret: str) -> dict:
        secret_value = parameters.get_secret(secret, transform="json")
        if isinstance(secret_value, dict):
            return secret_value
        else:
            raise ValueError("Unexpected secret value type:", type(secret_value))

    def uri_to_dict(uri) -> dict:
        split_uri = urllib.parse.urlsplit(uri)
        uri_dict = split_uri._asdict()
        uri_dict["username"] = split_uri.username
        uri_dict["password"] = split_uri.password
        uri_dict["hostname"] = split_uri.hostname
        uri_dict["port"] = split_uri.port

        return uri_dict

    def dict_to_uri(uri_dict: dict) -> str:
        scheme = uri_dict.get("scheme", "")

        netloc = ""
        if uri_dict.get("username"):
            netloc += uri_dict["username"]
        if uri_dict.get("password"):
            netloc += ":" + uri_dict["password"]
        if uri_dict.get("hostname"):
            netloc += "@" + uri_dict["hostname"]
        if uri_dict.get("port"):
            netloc += ":" + str(uri_dict["port"])

        if scheme == "oracledirectory":
            if uri_dict.get("database"):
                path = uri_dict["database"]
            elif uri_dict.get("servicename"):
                path = uri_dict["servicename"]
            else:
                path = uri_dict.get("path", "")

            query_parts = []
            if uri_dict.get("netloc"):
                query_parts.append(f"dir={uri_dict['netloc']}")
            if uri_dict.get("path"):
                if uri_dict.get("netloc"):
                    query_parts.append(f"file={uri_dict['path'].lstrip('/')}")
                else:
                    query_parts.append(f"file={uri_dict['path']}")
            query = "&".join(query_parts)
        else:
            path = uri_dict.get("path", "")
            query = uri_dict.get("query", "")

        fragment = uri_dict.get("fragment", "")

        return urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))

    if not secret:
        return uri

    logger.debug("Injecting secret: %s into URI: %s", secret, uri)

    secret_value: dict = get_secret_value(secret)
    uri_dict = uri_to_dict(uri)
    uri_dict.update(secret_value)

    uri_with_secret = dict_to_uri(uri_dict)
    logger.debug("URI with secret is: %s", uri_with_secret)

    return uri_with_secret


def request_handler(event: RequestModel, context: LambdaContext) -> HTTPResponse:
    # logger.debug("RequestModel: %s", repr(event))
    try:
        bytes_copied, took = copy(
            event.source_uri, event.destination_uri, event.compression_opt
        )
        rate_mbps = (float(bytes_copied) / 1024 / 1024) / took

        return build_response(
            HTTPStatus.OK,
            {"bytes_copied": bytes_copied, "took": took, "mbps": rate_mbps},
        )
    except Exception as e:
        return exception_handler(e)


@event_parser(model=Envelope)
def envelope_handler(event: Envelope, context: LambdaContext) -> HTTPResponse:
    return request_handler(parse_obj_as(RequestModel, event.body), context)


@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext) -> HTTPResponse:
    """
    sample events:
    event = {
        "source_uri": "oracledirectory://system:manager@host1/orclpdb1?dir=DATA_PUMP_DIR&file=export.dmp.gz",
        "destination_uri": "oracledirectory://system:manager@host2/orclpdb2?dir=DATA_PUMP_DIR&file=export.dmp",
    }
    event = {
        "source_uri": "scp://username:password@host1//opt/oracle/oradata/admin/ORCLCDB/dpdump/export.dmp",
        "destination_uri": "oracledirectory://system:manager@host2/orclpdb2?dir=DATA_PUMP_DIR&file=export.dmp",
    }
    event = {
        "source_uri": "s3://bucket_name/exports/export.dmp",
        "destination_uri": "oracledirectory://system:manager@host2/orclpdb2?dir=DATA_PUMP_DIR&file=export.dmp",
    }
    event = {
        "source_uri": "s3://bucket_name/exports/export.dmp",
        "destination_uri": "scp://username:password@host2//opt/oracle/oradata/admin/ORCLCDB/dpdump/export.dmp",
    }
    """
    logger.set_correlation_id(context.aws_request_id)

    try:
        if ENVELOPE:
            # Extract the request from outer envelope supplied as an env arg. Valid args
            # could potentially be any one of:
            # https://awslabs.github.io/aws-lambda-powertools-python/2.9.1/utilities/parser/#built-in-models
            # Currently the expectation is that the outer envelope is a AlbModel or
            # APIGatewayProxyEventModel
            envelope = getattr(models, ENVELOPE)
            return envelope_handler(parse(event=event, model=envelope), context)
        else:
            return request_handler(parse_obj_as(RequestModel, event), context)
    except ValidationError as e:
        return exception_handler(BadRequest(e))
