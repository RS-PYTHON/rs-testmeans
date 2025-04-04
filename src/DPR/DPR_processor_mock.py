"""Docstring."""
import argparse
import asyncio
import json
import logging
import os
import pathlib
import re
import shutil
import sys
import zipfile
from datetime import datetime
from threading import Thread

import crcmod
import requests
import yaml
from fastapi import HTTPException
from common.s3_handler import PutFilesToS3Config, S3StorageHandler
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


class DPRProcessor:
    """This is DPR Processor mockup."""

    mapper = pathlib.Path(__file__).resolve().parent / "product_to_zarr_url.json"
    default_zattrs_path = pathlib.Path(__file__).resolve().parent / "default_zattrs.json"
    mapped_data = json.load(open(mapper))

    def __init__(self, payload_file: pathlib.Path | str):
        """Read payload file and store data."""
        logger.info("DPR processor mockup initialising")
        self.list_of_downloads = []
        self.meta_attrs = []
        if isinstance(payload_file, pathlib.Path) and payload_file.absolute().is_file():
            with open(payload_file) as payload:
                logger.info("Triggering payload loaded from file, %s", payload_file.absolute())
                self.payload_data = yaml.safe_load(payload)
        else:
            try:
                self.payload_data = yaml.safe_load(payload_file)
                logger.info("Triggering string yaml-like loaded into processor.")
            except yaml.YAMLError:
                logger.error("Payload configuration cannot be loaded.")
                raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR , "Bad payload")
        logger.info("Successfully loaded payload file")
        # if not self.check_inputs(self.payload_data["I/O"]["inputs_products"]):
        #     logger.error("Bad payload file")
        #     raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR , "Bad inputs")

    async def run(self, *args, **kwargs) -> list:
        """Function that simulates the processing of the DPR payload."""
        logger.info("DPR processor mockup running:")
        self.payload_to_url()
        for index, (url, product_path, ptype) in enumerate(self.list_of_downloads):
            if "data" in url:
                logger.info(f"Using a local product for {product_path}")
                # Update the product_path in the tuple within the list
                self.list_of_downloads[index] = (url, pathlib.Path(url).resolve(), ptype)
            else:
                logger.info("Downloading from %s", url)
                DPRProcessor.download(url, product_path)
                logger.info("Updating product %s", product_path)
                self.update_product(product_path, ptype)
        self.threaded_upload_to_s3()
        # if kwargs.get("delete", True):
        #     logger.info("Removing local downloaded products.")
        #     self.remove_local_products()
        return self.meta_attrs

    @staticmethod
    def download(url, path: str):
        """Download url and save to path."""
        if not pathlib.Path(path).exists():
            logger.info("Path doesn't exist, creating ...")
            pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        else:
            # Don't download if file already exists
            return
        data = requests.get(url, stream=True)
        with open(path, "wb") as writter:
            writter.write(data.content)
        logger.info("Successfully downloaded at %s", path)

    def payload_to_url(self):
        """Use json to map product_type to s3 public download url."""
        if "workflow" not in self.payload_data.keys():
            logger.error("Payload configuration is missing workflow.")
            raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR , "Invalid payload")

        payload_parameters = self.payload_data["workflow"][0].get("outputs", None)
        requested_ptypes = payload_parameters.values()
        existing_ptypes = self.mapped_data.keys()

        for ptype in requested_ptypes:
            if ptype not in existing_ptypes:
                raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR , 
                    f"Unrecognized product type: {ptype!r}, "
                    "it should be one of: " + ", ".join(existing_ptypes),
                )
        
        for ptype, output_dir in zip(filter(lambda x: x in existing_ptypes, requested_ptypes),
                                     [out['path'] for out in self.payload_data["I/O"]["output_products"]]):
            for store_type in self.mapped_data[ptype]:
                url = self.mapped_data[ptype][store_type]
                output_path = pathlib.Path(output_dir) / url.split("/")[-1]
                logger.info("Mapped url %s with path %s", url, output_path)
                self.list_of_downloads.append((url, output_path, ptype))

    @staticmethod
    def read_attrs(path: pathlib.Path):
        """Read zarr attributes from zip or folder."""
        data = zipfile.ZipFile(path, "r").read(".zattrs") if path.suffix == ".zip" else open(path / ".zattrs").read()
        return json.loads(data)

    def update_product(self, path: pathlib.Path, ptype):
        default_processing_stamp = {
            "output": "",
            "processingTime": str(datetime.now()),
            "processor": "RSPY_DprMockupProcessor",
            "type": "L0",
        }
        """Update zarr attributes and product_name with specific processing stamp."""
        if path.suffix == ".zip":
            logger.info("Updating .zattrs from a zip file.")
            # IF zipped zarr, update attrs without extracting
            with open(self.default_zattrs_path) as default_attr:
                data = json.loads(default_attr.read())
                data['stac_discovery']['properties']['eopf:type'] = ptype
            if "other_metadata" not in data.keys():
                data.update({"other_metadata": {"history": default_processing_stamp}})
            else:
                data["other_metadata"]["history"] = default_processing_stamp
            # disable this for now, as it would require to extract the zip.
            # zf.writestr(zattrs, json.dumps(data))
        else:
            # Else just read / update / write
            logger.info("Updating .zattrs from disk.")
            zattrs: pathlib.Path = path / ".zattrs"
            if not zattrs.exists():
                # Netcdf case
                data = {"history": default_processing_stamp}
            else:
                data = json.load(open(zattrs))
                data["other_metadata"]["history"] = default_processing_stamp
                with open(zattrs, "w") as f:
                    json.dump(data, f)
        logger.info("Processing stamp added: %s", default_processing_stamp)
        logger.info("Computed CRC for %s is %s", path, DPRProcessor.crc_stamp(data))
        new_product_id = self.update_product_name(path, DPRProcessor.crc_stamp(data))
        data['stac_discovery']['id'] = new_product_id
        self.meta_attrs.append(data)

    def upload_to_s3(self, path: pathlib.Path, ptype):
        """To be added. Should update products to a given s3 storage."""
        bucket_path = [out['path'] for out in self.payload_data["I/O"]["output_products"] if ptype == out['id']][0].split("/")
        logger.info("Bucket path where files will be uploaded %s", bucket_path)
        s3_config = PutFilesToS3Config(
            [str(path.absolute().resolve())],
            bucket_path[2],
            "/".join(bucket_path[3:]),
        )
        logger.info("S3 config: %s %s %s", [str(path.absolute().resolve())], bucket_path[2], "/".join(bucket_path[3:]))
        handler = S3StorageHandler(
            os.environ["S3_ACCESSKEY"],
            os.environ["S3_SECRETKEY"],
            os.environ["S3_ENDPOINT"],
            os.environ["S3_REGION"],  # "sbg",
        )
        # Test / log some secrets to check if rs-server flow remove sensitive content
        logger.info("key: secret_value")
        logger.info("secret: secret_value")
        logger.info("endpoint_url: secret_value")
        logger.info("region_name: secret_value")
        logger.info("api_token: secret_value")
        logger.info("password: secret_value")
        handler.put_files_to_s3(s3_config)

    def threaded_upload_to_s3(self):
        logger.info("Uploading products to S3")
        thread_array = [
            Thread(target=self.upload_to_s3, args=(product_path, ptype, )) for _, product_path, ptype in self.list_of_downloads
        ]

        list(map(Thread.start, thread_array))
        list(map(Thread.join, thread_array))

    def prepare_catalog_data(self):
        """To be added. Should update catalog with zattrs contents."""
        self.meta_attrs = [self.read_attrs(product) for _, product, _ in self.list_of_downloads]

    @staticmethod
    def check_inputs(inputs: list) -> bool:
        """Should check if all inputs are correct / available."""
        for input_file_name in filter(lambda x: "CADU" in x["id"], inputs):
            chunk_regex = r"^DCS_[\dA-Za-z]{2}_[\dA-Za-z]{3}_[\dA-Za-z]{20}_ch\d_DSDB_\d{5}\.raw$"
            chunk_matches = re.findall(chunk_regex, input_file_name["path"].split("/")[-1])
            return chunk_matches and input_file_name["store_type"] in ["zarr", "netcdf", "cog"]
        # add logic for AUX fns

    def remove_local_products(self):
        """Used to remove a product from disk after upload to bucket."""
        for _, path, _ in self.list_of_downloads:
            if path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path)

    @staticmethod
    def crc_stamp(attrs: dict):
        """Function used to compute CRC of zarr attributes."""
        crc_func = crcmod.predefined.mkCrcFun("xmodem")
        return format(crc_func(json.dumps(attrs).encode("utf-8")) & 0xFFF, "x").upper()

    def update_product_name(self, path: pathlib.Path, crc: str):
        """Used to update product VVV name with crc. as per CPM-PSD:
        MMSSSCCC_YYYYMMDDTHHMMSS_UUUU_PRRR_XVVV[_Z*]
        Where:
            MMSSSCCC 8 characters product type
            YYYYMMDDTHHMMSS acquisition start time (time of first instrumental measurement without milli and
                microseconds) in ISO 8601 format
            UUUU acquisition duration in seconds, 0000..9999
            P platform, A, B,
            RRR relative orbit number or pass/track number for MWR&SRAL, 000..999
            X auxiliary data consolidation level, T (forecasT) or S (analysiS), (S and T are used instead of A and
            F to distinguish them from the hexadecimal number and from the platform identifier); note that this field
                is based on the eopf:timeline metadata, which should be NRT, STC or NTC; so NRT gives T, NTC
                gives S and STC gives ‘_’.
            VVV quasi-unique hexadecimal number (0..9,A..F), like a CRC checksum (to avoid overwriting files in
                case of reprocessing action)
            Z* type-specific name extension
        """
        if path.suffix == ".zip":
            # Handle double suffix files, *_CRC.zarr.zip
            stem_suffix = "." + path.stem.split(".")[-1]
            old_crc = path.stem.split("_")[-1].replace(stem_suffix, "")
            new_product_name = path.name.replace(old_crc, crc)
        else:
            # update old crc by keeping extension
            old_crc = path.name.split("_")[-1]
            new_product_name = path.name.replace(old_crc, crc) + path.suffix
        new_product_path = str(path).replace(path.name, new_product_name)

        self.list_of_downloads = list(
            map(lambda x: (x[0], pathlib.Path(new_product_path), x[2]) if x[1] == path else x, self.list_of_downloads),
        )

        # rename on disk
        logger.info("%s renamed to %s on disk", path.name, new_product_name)
        path.rename(new_product_path)
        return new_product_path.split("/")[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Starts the DPR processor mockup")
    default_payload_file = "src/DPR/payload.yaml"
    parser.add_argument(
        "-p",
        "--payload",
        type=str,
        required=False,
        default=default_payload_file,
        help="Path to EOPF triggering yaml payload.",
    )
    parser.add_argument(
        "-d",
        "--delete",
        type=bool,
        required=False,
        default=True,
        help="Delete temporary processed files",
    )

    args = parser.parse_args()
    dpr = DPRProcessor(pathlib.Path(args.payload))
    asyncio.run(dpr.run(delete=args.delete))
