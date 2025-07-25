from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime
import json
import pathlib
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


Base = declarative_base()

class Product(Base):
    __tablename__ = "products"

    id = Column(String, primary_key=True)
    name = Column(String)
    content_type = Column(String)
    content_length = Column(Integer)
    origin_date = Column(DateTime)
    publication_date = Column(DateTime)
    eviction_date = Column(DateTime)

    # ContentDate
    contentdate_start = Column(DateTime)
    contentdate_end = Column(DateTime)

    attributes_platformShortName = Column(String)
    attributes_platformSerialIdentifier = Column(String)
    attributes_productType = Column(String)
    attributes_processingCenter = Column(String)
    attributes_processorVersion = Column(String)
    attributes_beginningDateTime = Column(DateTime)
    attributes_endingDateTime = Column(DateTime)
    attributes_processingDate = Column(DateTime)

    checksum_algorithm = Column(String)
    checksum_value = Column(String)
    checksum_date = Column(DateTime)

def parse_iso8601(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))

def extract_attr(attributes: list, name: str) -> str | None:
    for attr in attributes:
        if attr["Name"] == name:
            val = attr["Value"]
            if "DateTime" in attr.get("ValueType", ""):
                return parse_iso8601(val)
            return val
    return None

def dict_to_product(data: dict) -> Product:
    attributes = data.get("Attributes", [])
    checksums = data.get("Checksum", [])
    first_checksum = checksums[0] if checksums else {}

    return Product(
        id=data["Id"],
        name=data["Name"],
        content_type=data["ContentType"],
        content_length=int(data["ContentLength"]),
        origin_date=parse_iso8601(data["OriginDate"]),
        publication_date=parse_iso8601(data["PublicationDate"]),
        eviction_date=parse_iso8601(data["EvictionDate"]),

        contentdate_start=parse_iso8601(data["ContentDate"]["Start"]),
        contentdate_end=parse_iso8601(data["ContentDate"]["End"]),

        attributes_platformShortName=extract_attr(attributes, "platformShortName"),
        attributes_platformSerialIdentifier=extract_attr(attributes, "platformSerialIdentifier"),
        attributes_productType=extract_attr(attributes, "productType"),
        attributes_processingCenter=extract_attr(attributes, "processingCenter"),
        attributes_processorVersion=extract_attr(attributes, "processorVersion"),
        attributes_beginningDateTime=extract_attr(attributes, "beginningDateTime"),
        attributes_endingDateTime=extract_attr(attributes, "endingDateTime"),
        attributes_processingDate=extract_attr(attributes, "processingDate"),

        checksum_algorithm=first_checksum.get("Algorithm"),
        checksum_value=first_checksum.get("Value"),
        checksum_date=parse_iso8601(first_checksum["ChecksumDate"]) if "ChecksumDate" in first_checksum else None
    )

data_path = PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config" / "Catalog" / "GETFileResponse.json"


with open(data_path) as df:
    data = json.loads(df.read())['Data']

engine = create_engine("sqlite:///produse.db")
Base.metadata.create_all(engine)

with Session(engine) as session:
    for dict_product in data:
        product = dict_to_product(dict_product)
        session.add(product)
        session.commit()