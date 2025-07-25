import json
import pathlib
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class ChecksumItem:
    Algorithm: str
    Value: str
    ChecksumDate: datetime


@dataclass
class ContentDate:
    Start: datetime
    End: datetime


@dataclass
class AttributeItem:
    odata_type: str
    Name: str
    ValueType: str
    Value: str


@dataclass
class Product:
    Id: str
    Name: str
    ContentType: str
    ContentLength: int
    OriginDate: datetime
    PublicationDate: datetime
    EvictionDate: datetime
    Checksum: List[ChecksumItem]
    ContentDate: ContentDate
    Attributes: List[AttributeItem]

def parse_iso8601(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def parse_product(data: dict) -> Product:
    return Product(
        Id=data["Id"],
        Name=data["Name"],
        ContentType=data["ContentType"],
        ContentLength=int(data["ContentLength"]),
        OriginDate=parse_iso8601(data["OriginDate"]),
        PublicationDate=parse_iso8601(data["PublicationDate"]),
        EvictionDate=parse_iso8601(data["EvictionDate"]),
        Checksum=[
            ChecksumItem(
                Algorithm=chk["Algorithm"],
                Value=chk["Value"],
                ChecksumDate=parse_iso8601(chk["ChecksumDate"])
            )
            for chk in data.get("Checksum", [])
        ],
        ContentDate=ContentDate(
            Start=parse_iso8601(data["ContentDate"]["Start"]),
            End=parse_iso8601(data["ContentDate"]["End"])
        ),
        Attributes=[
            AttributeItem(
                odata_type=attr["@odata.type"],
                Name=attr["Name"],
                ValueType=attr["ValueType"],
                Value=attr["Value"]
            )
            for attr in data.get("Attributes", [])
        ]
    )






data_path = PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config" / "Catalog" / "GETFileResponse.json"


with open(data_path) as df:
    data = json.loads(df.read())['Data']

for dict_product in data:
    product = parse_product(dict_product)