import json
import os
import pathlib
import shutil

import boto3
import pytest
import yaml
from moto.server import ThreadedMotoServer
import asyncio
from src.DPR.DPR_processor_mock import DPRProcessor

from .conftest import export_aws_credentials


def test_invalid_payload_file():  # noqa: D103
    yamlstr = """I/O:
  inputs_products:
  - id: CADU1
    path: chunk/S1/S1A_20231121072204051312/bad_chunk_name.raw
    """
    data = yaml.safe_load(yamlstr)
    # Test fail on input chunk regex name
    with pytest.raises(ValueError):
        dpr_processor = DPRProcessor(yaml.dump(data))
        dpr_processor.payload_to_url()
    yamlstr = """I/O:
      inputs_products:
      - id: CADU1
        path: chunk/S1/S1A_20231121072204051312/DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
        store_params: {}"""
    data = yaml.safe_load(yamlstr)
    # Test fail on workflow descriptor
    with pytest.raises(ValueError):
        dpr_processor = DPRProcessor(yaml.dump(data))
        asyncio.run(dpr_processor.run())
    yamlstr = """
    workflow:
    - step: 1
    I/O:
      inputs_products:
      - id: CADU1
        path: chunk/S1/S1A_20231121072204051312/DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
        store_params: {}
    """
    data = yaml.safe_load(yamlstr)
    # Test fail on workflow missing parameters descriptors
    with pytest.raises(ValueError):
        dpr_processor = DPRProcessor(yaml.dump(data))
        asyncio.run(dpr_processor.run())


def test_list_of_downloadableable_products():
    yamlstr = """
    I/O:
      inputs_products:
      - id: CADU1
        path: DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
      output_products:
      - id: outputs
        path: src/DPR/data/ # output folder or S3 bucket
    workflow:
    - step: 1
      parameters:
        product_types:
        - S1SEWRAW
        - S1SIWRAW
    """
    data = yaml.safe_load(yamlstr)
    dpr_processor = DPRProcessor(yaml.dump(data))
    dpr_processor.payload_to_url()
    assert dpr_processor.list_of_downloads


@pytest.mark.unit
@pytest.mark.parametrize(
    "input_data_path, expected_new_product_name",
    [
        (
                "tests/data/S1SEWRAW_20230103T225516_0038_A003_T290.zarr",
                "tests/data/S1SEWRAW_20230103T225516_0038_A003_TEST_CRC.zarr",
        ),
        (
                "tests/data/S1SEWRAW_20230103T225516_0038_A003_T290.zarr.zip",
                "tests/data/S1SEWRAW_20230103T225516_0038_A003_TEST_CRC.zarr.zip",
        ),
    ],
)
def test_dpr_product_rename(mocker, input_data_path, expected_new_product_name):
    yamlstr = """
    I/O:
      inputs_products:
      - id: CADU1
        path: DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
      output_products:
      - id: outputs
        path: src/DPR/data/ # output folder or S3 bucket
    workflow:
    - step: 1
      parameters:
        product_types:
        - S1SEWRAW
    """
    dpr_mockup_processor = DPRProcessor(yaml.dump(yaml.safe_load(yamlstr)))
    # Don't actually rename on disk, just mock it.
    mock_rename = mocker.patch("pathlib.Path.rename", return_value=None, autospec=True)
    dpr_mockup_processor.update_product_name(pathlib.Path(input_data_path), "TEST_CRC")
    mock_rename.assert_called_once()
    # Check that pathlib.Path.rename is called with the right parameters
    mock_rename.assert_called_with(pathlib.PosixPath(input_data_path), expected_new_product_name)


@pytest.mark.unit
@pytest.mark.parametrize(
    "input_data_path, expected_processing_stamp",
    [
        (
                "tests/data/S1SEWRAW_20230103T225516_0038_A003_T290.zarr",
                "RSPY_DprMockupProcessor",
        ),
    ],
)
def test_dpr_attrs_update(mocker, input_data_path, expected_processing_stamp):
    yamlstr = """
    I/O:
      inputs_products:
      - id: CADU1
        path: DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
      output_products:
      - id: outputs
        path: src/DPR/data/ # output folder or S3 bucket
    workflow:
    - step: 1
      parameters:
        product_types:
        - S1SEWRAW
    """
    initial_data = json.load(open(pathlib.Path(input_data_path) / ".zattrs"))
    mocker.patch("src.DPR.DPR_processor_mock.DPRProcessor.update_product_name", return_value=None, autospec=True)

    dpr = DPRProcessor(yaml.dump(yaml.safe_load(yamlstr)))
    dpr.update_product(pathlib.Path(input_data_path))
    updated_data = json.load(open(pathlib.Path(input_data_path) / ".zattrs"))
    # Check that processing history timestamp was updated, and processor name is correct
    assert initial_data != updated_data
    assert expected_processing_stamp in updated_data["other_metadata"]["history"]["processor"]
    # Replace with initial data to avoid side effects
    json.dump(initial_data, open(pathlib.Path(input_data_path) / ".zattrs", "w"), indent=4)


# TC-001 / 002 / 003: Call the mockup with S1 L0 EW / local directory.
# Check that zarr directory is written in the output directory and that zarr/.zattrs datetime fields
# contain the current datetime. For unittest s1l2OCN was selected due to small size and faster download speed.
# Only supports zarr at the moment, due to difficult attrs check on cogs / netcdfs stored on s3.
@pytest.mark.unit
@pytest.mark.parametrize(
    "product_type, s3_outputpath",
    [
        (
                "S1SSMOCN",
                ["S1SSMOCN_20220708T000110_0019_S004__***.zarr.zip",
                 "S1SSMOCN_20220708T000110_0019_S004__***.cog.zip",
                 "S1SSMOCN_20220708T000110_0019_S004__***.nc"]
        ),
    ],
)
def test_s1_l2_ocn_process(product_type, s3_outputpath):
    yamlstr = f"""
    I/O:
      inputs_products:
      - id: CADU1
        path: DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
      output_products:
      - id: outputs
        path: s3://test-data/ # output folder or S3 bucket
    workflow:
    - step: 1
      parameters:
        product_types:
        - {product_type}
    """
    # Start moto s3 server
    export_aws_credentials()
    server = ThreadedMotoServer(port=5555)
    server.start()
    s3_client = boto3.client("s3", endpoint_url="http://127.0.0.1:5555")
    s3_client.create_bucket(Bucket="test-data")

    # Run processor and recover metadata
    async def run_processor():
        dpr = DPRProcessor(yaml.dump(yaml.safe_load(yamlstr)))
        attrs = await dpr.run()
        return attrs

    attrs = asyncio.run(run_processor())
    # Use attrs to compute new product name, since it changes based on datetime
    stamps = [DPRProcessor.crc_stamp(attr) for attr in attrs]

    # Create new product name replacing *** with newly compute crc stamp.
    new_product_names = [new_name.replace("***", stamps[idx]) for idx, new_name in enumerate(s3_outputpath)]
    # Check that expected path was created and product was updated into s3.
    uploaded_s3_files = [file["Key"] for file in s3_client.list_objects(Bucket="test-data")["Contents"]]
    assert sorted(uploaded_s3_files) == sorted(new_product_names)
    # Check that temp download dir was not cleared
    # check that attrs were updated with correct processor name
    assert attrs[0]["other_metadata"]["history"]["processor"] == "RSPY_DprMockupProcessor"

    # clear up
    shutil.rmtree("s3://test-data/")
    server.stop()


#  TC-003: Call the mockup with same arguments as previous test. Check that the difference between the outputs of TC-002
#  and TC-003 concern the datetime fields and the CRC in the product name.

# Test overlapping products in the same s3 folder.
@pytest.mark.unit
@pytest.mark.parametrize(
    "product_type, bucket",
    [
        ("S1SSMOCN", "test-data-reprocessing-first"),
        ("S1SSMOCN", "test-data-reprocessing-second")
    ],
)
def test_s1_l2_ocn_reprocessing(product_type, bucket):
    yamlstr = f"""
    I/O:
      inputs_products:
      - id: CADU1
        path: DCS_04_S1A_20231121072204051312_ch1_DSDB_00023.raw
        store_type: zarr
      output_products:
      - id: outputs
        path: s3://{bucket} # output folder or S3 bucket
    workflow:
    - step: 1
      parameters:
        product_types:
        - {product_type}
    """

    async def run_processor():
        dpr = DPRProcessor(yaml.dump(yaml.safe_load(yamlstr)))
        attrs = await dpr.run()
        return attrs

    # Start moto s3 server
    export_aws_credentials()
    server = ThreadedMotoServer(port=5555)
    server.start()
    s3_client = boto3.client("s3", endpoint_url="http://127.0.0.1:5555")
    s3_client.create_bucket(Bucket=bucket)
    for _ in range(5):
        # Run the test 5 times, to make sure that new products are created each time, and no overlaps occur
        attrs = asyncio.run(run_processor())
    # 5 runs with 3 generated files each time
    assert len([file["Key"] for file in s3_client.list_objects(Bucket=bucket)["Contents"]]) == 5 * 3
    server.stop()
