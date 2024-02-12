"""Docstring."""
import argparse
import json
import os
import pathlib
import re
import shutil
import zipfile
from datetime import datetime
from threading import Thread

import crcmod
import requests
import yaml
from s3_handler import PutFilesToS3Config, S3StorageHandler


class DPRProcessor:
    """This is DPR Processor mockup."""

    mapper = pathlib.Path(__file__).resolve().parent / "product_to_zarr_url.json"
    mapped_data = json.load(open(mapper))
    DEFAULT_PROCESSING_STAMP = {
        "output": "",
        "processingTime": str(datetime.now()),
        "processor": "RSPY_DprMockupProcessor",
        "type": "L0",
    }

    def __init__(self, payload_file):
        """Read payload file and store data."""
        self.list_of_downloads = []
        self.meta_attrs = []
        if pathlib.Path(payload_file).is_file():
            with open(payload_file) as payload:
                self.payload_data = yaml.safe_load(payload)
        else:
            try:
                self.payload_data = yaml.safe_load(payload_file)
            except yaml.YAMLError:
                raise ValueError("Bad payload")
        if not self.check_inputs(self.payload_data["I/O"]["inputs_products"]):
            raise ValueError("Bad inputs")

    def run(self, *args, **kwargs) -> list:
        """Function that simulates the processing of the DPR payload."""
        self.payload_to_url()
        for url, product_path in self.list_of_downloads:
            DPRProcessor.download(url, product_path)
            self.update_product(product_path)

        self.threaded_upload_to_s3()
        self.prepare_catalog_data()
        if kwargs.get("delete", True):
            self.remove_local_products()
        return self.meta_attrs

    @staticmethod
    def download(url, path: str):
        """Download url and save to path."""
        if not pathlib.Path(path).exists():
            pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        data = requests.get(url, stream=True)
        with open(path, "wb") as writter:
            writter.write(data.content)

    def payload_to_url(self):
        """Use json to map product_type to s3 public download url."""
        if "workflow" not in self.payload_data.keys():
            raise ValueError("Invalid payload")
        if "parameters" not in self.payload_data["workflow"][0].keys():
            raise ValueError("Invalid payload")

        payload_parameters = self.payload_data["workflow"][0].get("parameters", None)
        outputs_dir = self.payload_data["I/O"]["output_products"][0].get("path", None)

        for ptype in filter(lambda x: x in self.mapped_data.keys(), payload_parameters["product_types"]):
            url = self.mapped_data[ptype]
            output_path = pathlib.Path(outputs_dir) / url.split("/")[-1]
            self.list_of_downloads.append((url, output_path))

    @staticmethod
    def read_attrs(path: pathlib.Path):
        """Read zarr attributes from zip or folder."""
        if ".zip" in path.absolute().as_posix():
            archive = zipfile.ZipFile(path, "r")
            return json.loads(archive.read(".zattrs"))
        with open(path + "/.zattrs") as attrs:
            return json.loads(attrs.read())

    def update_product(self, path: pathlib.Path):
        """Update zarr attributes and product_name with specific processing stamp."""
        data = dict()
        if ".zip" in path.absolute().as_posix():
            # IF zipped zarr, update attrs without extracting
            with zipfile.ZipFile(path, "a") as zf:
                zattrs = zf.getinfo(".zattrs")
                with zf.open(zattrs) as f:
                    data = json.loads(f.read())
                data["other_metadata"]["history"] = self.DEFAULT_PROCESSING_STAMP
                zf.writestr(zattrs, json.dumps(data))
        else:
            # Else just read / update / write
            zattrs: pathlib.Path = path / ".zattrs"
            data = json.load(open(zattrs))
            data["other_metadata"]["history"] = self.DEFAULT_PROCESSING_STAMP
            with open(zattrs, "w") as f:
                json.dump(data, f)
        self.update_product_name(path, DPRProcessor.crc_stamp(data))

    @staticmethod
    def upload_to_s3(path: pathlib.Path):
        """To be added. Should update products to a given s3 storage."""
        handler = S3StorageHandler(
            os.environ["S3_ACCESSKEY"],
            os.environ["S3_SECRETKEY"],
            os.environ["S3_ENDPOINT"],
            os.environ["S3_REGION"],  # "sbg",
        )
        bucket_path = "s3://test-data/zarr/dpr_processor_output/".split("/")
        s3_config = PutFilesToS3Config(
            [str(path.absolute().resolve())],
            bucket_path[2],
            "/".join(bucket_path[3:]),
        )
        handler.put_files_to_s3(s3_config)

    def threaded_upload_to_s3(self):
        thread_array = [
            Thread(target=DPRProcessor.upload_to_s3, args=(product_path,)) for _, product_path in self.list_of_downloads
        ]
        for thrd in thread_array:
            thrd.start()

        for thrd in thread_array:
            thrd.join()

        # map(Thread.start, thread_array)
        # map(Thread.join, thread_array)

    def prepare_catalog_data(self):
        """To be added. Should update catalog with zattrs contents."""
        self.meta_attrs = [self.read_attrs(product) for _, product in self.list_of_downloads]

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
        for _, path in self.list_of_downloads:
            if path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path)

    @staticmethod
    def crc_stamp(attrs: dict):
        """Function used to compute CRC of zarr attributes."""
        crc_func = crcmod.predefined.mkCrcFun("xmodem")
        return str(hex((crc_func(json.dumps(attrs).encode("utf-8")) & 0xFFF))).replace("0x", "").upper()

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
        if ".zip" in path.absolute().as_posix():
            stem_suffix = "." + path.stem.split(".")[-1]
            old_crc = path.stem.split("_")[-1].replace(stem_suffix, "")
            new_product_name = path.name.replace(old_crc, crc)
        else:
            # update old crc by keeping extension
            old_crc = path.name.split("_")[-1]
            new_product_name = path.name.replace(old_crc, crc) + path.suffix
        new_product_path = str(path).replace(path.name, new_product_name)

        self.list_of_downloads = list(
            map(lambda x: (x[0], pathlib.Path(new_product_path)) if x[1] == path else x, self.list_of_downloads),
        )

        # rename on disk
        path.rename(new_product_path)


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
    dpr = DPRProcessor(args.payload)
    dpr.run(delete=args.delete)
