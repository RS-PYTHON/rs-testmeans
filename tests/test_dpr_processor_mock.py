import pathlib

import pytest
import yaml

from src.DPR.DPRProcessor import DPRProcessor


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
        dpr_processor.run()
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
        dpr_processor.run()


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


@pytest.mark.unit()
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
        )
    ],
)
def test_dpr_product_rename(mocker, input_data_path, expected_new_product_name):
    # Don't actually rename on disk, just mock it.
    mock_rename = mocker.patch("pathlib.Path.rename", return_value=None, autospec=True)
    DPRProcessor.update_product_name(pathlib.Path(input_data_path), "TEST_CRC")
    mock_rename.assert_called_once()
    # Check that pathlib.Path.rename is called with the right parameters
    mock_rename.assert_called_with(pathlib.PosixPath(input_data_path), expected_new_product_name)
