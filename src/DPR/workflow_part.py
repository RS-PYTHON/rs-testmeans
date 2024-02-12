import pathlib

from DPRProcessor import DPRProcessor


def prepare_yaml() -> pathlib.Path | str:
    # Some logic that creates a yaml file and pass it to DPRProcessor.
    pass


def update_catalog(list_of_stac_attrs):
    # Retrieve list of stac attrs from DPR processor and update catalog.
    # with fastapi pgstac.
    pass


if __name__ == "__main__":
    # ingestion part

    payload_file = prepare_yaml()
    dpr_mockup = DPRProcessor(payload_file)
    processed_products_attrs = dpr_mockup.run()
    update_catalog(processed_products_attrs)

    # rest of workflow
