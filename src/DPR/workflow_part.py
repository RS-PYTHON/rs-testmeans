# Copyright 2023-2026 Airbus, CS Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pathlib

from DPR_processor_mock import DPRProcessor


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
