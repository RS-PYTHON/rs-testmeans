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

import requests
import s3_handler
import yaml


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
        with open(payload_file) as payload:
            self.payload_data = yaml.safe_load(payload)

    def run(self):
        """Function that simulates the processing of the DPR payload."""
        self.payload_to_url()
        if not self.check_inputs(self.payload_data["I/O"]["inputs_products"]):
            return

        for url, product_path in self.list_of_downloads:
            DPRProcessor.download(url, product_path)
            self.update_zattrs(product_path)

        self.threaded_upload_to_s3()
        self.update_catalog()

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
        payload_parameters = self.payload_data["workflow"][0]["parameters"]
        outputs_dir = self.payload_data["I/O"]["output_products"][0]["path"]
        for product in payload_parameters["product_types"]:
            if product in self.mapped_data.keys():
                url = self.mapped_data[product]
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

    def update_zattrs(self, path: pathlib.Path):
        """Update zarr attributes with specific processing stamp."""
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
            attrs = json.load(open(zattrs))
            attrs["other_metadata"]["history"] = self.DEFAULT_PROCESSING_STAMP
            with open(zattrs, "w") as f:
                json.dump(attrs, f)

    @staticmethod
    def upload_to_s3(path: pathlib.Path):
        """To be added. Should update products to a given s3 storage."""
        handler = s3_handler.S3StorageHandler(
            os.environ["S3_ACCESSKEY"],
            os.environ["S3_SECRETKEY"],
            os.environ["S3_ENDPOINT"],
            os.environ["S3_REGION"],  # "sbg",
        )

        bucket_path = "s3://test-data/zarr/dpr_processor_output/".split("/")
        s3_config = s3_handler.PutFilesToS3Config(
            [str(path.absolute().resolve())],
            bucket_path[2],
            "/".join(bucket_path[3:]),
        )
        handler.put_files_to_s3(s3_config)

    def threaded_upload_to_s3(self):
        thread_array = list()
        for idx, (_, product_path) in enumerate(self.list_of_downloads):
            thread_array.append(Thread(target=DPRProcessor.upload_to_s3, args=(product_path,)))
            thread_array[idx].start()

        for dwn_thread in thread_array:
            dwn_thread.join()

    def update_catalog(self):
        """To be added. Should update catalog with zattrs contents."""
        for _, product in self.list_of_downloads:
            attrs = self.read_attrs(product)

    @staticmethod
    def check_inputs(inputs: list) -> bool:
        """To be added. Should check if all inputs are correct / available."""
        for input_file_name in inputs:
            if "CADU" in input_file_name["id"]:
                chunk_regex = r"^DCS_[\dA-Za-z]{2}_[\dA-Za-z]{3}_[\dA-Za-z]{20}_ch\d_DSDB_\d{5}\.raw$"
                chunk_matches = re.findall(chunk_regex, input_file_name["path"].split("/")[-1])
                return chunk_matches and input_file_name["store_type"] in ["zarr", "netcdf", "cog"]

    def remove_product(self, path: pathlib.Path):
        """Used to remove a product from disk after upload to bucket."""
        if path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)


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

    args = parser.parse_args()
    dpr = DPRProcessor(args.payload)
    dpr.run()
