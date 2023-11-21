"""Docstring to be added."""

import argparse
import logging
import os

# import glob
import shutil
import signal
import sys
import time

from prefect import flow, get_run_logger
from prefect_dask.task_runners import DaskTaskRunner

sys.path.insert(0, os.path.join(os.path.dirname(sys.path[0]), "../../", "rs-server/src/"))
from ingestion.ingest_cadip_data import execute  # noqa
import s3_storage_handler  # noqa


def os_sig_handler(signal_number, frame):
    """Docstring to be added."""
    print("Received the signal {}".format(signal_number))

    if signal_number in {
        signal.SIGTERM,
        signal_number == signal.SIGINT,
        signal_number == signal.SIGQUIT,
        signal_number == signal.SIGABRT,
    }:
        print(
            "Interruption caught ! The node will be probably terminated. \
SIGTERM will be sent to all running processes and exit",
        )
        s3_storage_handler.aws_terminating_node_notice = True
        return
    print("The signal received is not SIGTERM/SIGINT/SIGQUIT/SIGABRT. Doing nothing...")


@flow(task_runner=DaskTaskRunner())
def s3_handler(action, list_with_files, bucket, prefix, max_runners=10):
    """Docstring to be added."""
    # get the Prefect logger
    logger = get_run_logger()

    nb_of_tasks = min(max_runners, len(list_with_files))
    lists_per_tasks = [None] * nb_of_tasks
    current_idx = 0
    for col_file in list_with_files:
        if lists_per_tasks[current_idx] is None:
            lists_per_tasks[current_idx] = list()
        lists_per_tasks[current_idx].append(col_file)
        if current_idx == (nb_of_tasks - 1):
            current_idx = 0
        else:
            current_idx += 1

    logger.info("lists_per_tasks = {}".format(lists_per_tasks))
    idx = 0
    for list_per_task in lists_per_tasks:
        if list_per_task[0] is None:
            continue
        if action == "download":
            s3_storage_handler.prefect_get_keys_from_s3.submit(list_per_task, bucket, prefix, idx)
        elif action == "upload":
            s3_storage_handler.prefect_put_files_to_s3.submit(list_per_task, bucket, prefix, idx)
        else:
            logger.error("The action has to be download / upload. Instead is {}".format(action))
            sys.exit(-1)
        idx += 1


@flow(task_runner=DaskTaskRunner())
def module_ard_pre_processor(bucket, max_runners):
    """Docstring to be added."""
    # TODO execute client for CADIP mockup server
    execute("ingestionParameters.json")

    # TODO simulate the execution

    list_with_files = s3_storage_handler.files_to_be_uploaded(["ard_data"], logger)  # type: ignore
    if len(list_with_files) == 0:
        return False

    s3_prefix = "ard-data-{}".format(time.strftime("%Y%m%d_%H%M%S"))
    s3_handler("upload", list_with_files, bucket, s3_prefix, max_runners)
    return "s3://{}/{}".format(bucket, s3_prefix)


@flow(task_runner=DaskTaskRunner())
def module_classification_processor(bucket, ard_data_prefix, aux_data_prefix, max_runners):
    """Docstring to be added."""
    # TODO execute client for ADGS mockup server

    # download ard data (intermediary results) and auxiliary results.
    # For the demo sake, will presume that all of the files are in the same bucket
    list_with_files = s3_storage_handler.files_to_be_downloaded(
        bucket,
        [
            ard_data_prefix,
            aux_data_prefix,
        ],
        logger,
    )  # type: ignore
    if len(list_with_files) == 0:
        return False
    local_prefix = "TMP_ard_aux_data"
    s3_handler("download", list_with_files, bucket, local_prefix, max_runners)

    # TODO simulate the execution

    # TODO ! delete temp data !!!!!!

    shutil.rmtree(local_prefix, ignore_errors=True)

    # upload the final product
    list_with_files = s3_storage_handler.files_to_be_uploaded(["final_product"], logger)  # type: ignore
    if len(list_with_files) == 0:
        return False

    s3_prefix = "final-product-{}".format(time.strftime("%Y%m%d_%H%M%S"))
    s3_handler("upload", list_with_files, bucket, s3_prefix, max_runners)
    return "s3://{}/{}".format(bucket, s3_prefix)


"""
#@flow(task_runner=DaskTaskRunner())
def demo_flow(bucket, max_runners=10):
    # get the Prefect logger
    logger = get_run_logger()

    # start task Pre_Processor
    # wait to end
    # start task ClassificatioProcessor



    nb_of_tasks = min(max_runners, len(list_with_files))
    lists_per_tasks = [None] * nb_of_tasks
    current_idx = 0
    for col_file in list_with_files:
        if lists_per_tasks[current_idx] is None:
            lists_per_tasks[current_idx] = list()
        lists_per_tasks[current_idx].append(col_file)
        if current_idx == (nb_of_tasks - 1):
            current_idx = 0
        else:
            current_idx += 1

    logger.info("lists_per_tasks = {}".format(lists_per_tasks))
    idx = 0
    for list_per_task in lists_per_tasks:
        if list_per_task[0] is None:
            continue
        if action == "download":
            s3_storage_handler.prefect_get_keys_from_s3.submit(list_per_task, bucket, prefix, idx)
        elif action == "upload":
            s3_storage_handler.prefect_put_files_to_s3.submit(list_per_task, bucket, prefix, idx)
        else:
            logger.error("The action has to be download / upload. Instead is {}".format(action))
            sys.exit(-1)
        idx += 1
"""

if __name__ == "__main__":
    """Docstring to be added."""
    log_folder = "./demo/"
    os.makedirs(log_folder, exist_ok=True)
    log_formatter = logging.Formatter("[%(asctime)-20s] [%(name)-10s] [%(levelname)-6s] %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(log_formatter)
    log_filename = log_folder + "s3_handler_" + time.strftime("%Y%m%d_%H%M%S") + ".log"
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(log_formatter)

    logger = logging.getLogger("upload_files")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    logger.propagate = False

    logger.addHandler(console_handler)

    logger.addHandler(file_handler)

    signal.signal(signal.SIGINT, os_sig_handler)
    signal.signal(signal.SIGQUIT, os_sig_handler)
    signal.signal(signal.SIGILL, os_sig_handler)
    signal.signal(signal.SIGTRAP, os_sig_handler)
    signal.signal(signal.SIGABRT, os_sig_handler)
    signal.signal(signal.SIGSEGV, os_sig_handler)
    signal.signal(signal.SIGTERM, os_sig_handler)

    parser = argparse.ArgumentParser(
        description="Starts the demo for sprint 1 phase",
    )
    parser.add_argument("-b", "--bucket", type=str, required=True, help="Bucket to work with")

    parser.add_argument("-s", "--secret-file", type=str, required=True, help="File with the secrets")

    parser.add_argument(
        "-t",
        "--max-tasks",
        type=int,
        required=False,
        help="Maximum number of prefect tasks. Default 10",
        default=10,
    )

    args = parser.parse_args()
    secrets = {
        "s3endpoint": None,
        "accesskey": None,
        "secretkey": None,
    }
    if not s3_storage_handler.get_secrets(secrets, args.secret_file, logger=logger):  # type: ignore
        logger.error("Could not get the aws secrets")
        sys.exit(-1)

    os.environ["S3_ENDPOINT"] = secrets["s3endpoint"] if secrets["s3endpoint"] is not None else ""
    os.environ["S3_ACCESS_KEY_ID"] = secrets["accesskey"] if secrets["accesskey"] is not None else ""
    os.environ["S3_SECRET_ACCESS_KEY"] = secrets["secretkey"] if secrets["secretkey"] is not None else ""
    os.environ["S3_REGION"] = "sbg"

    # start a flow
    ard_location = module_ard_pre_processor(args.bucket, args.max_tasks)
    bucket, _, key = s3_storage_handler.get_s3_data(ard_location)  # type: ignore
    logger.debug(
        "ard_location {} | get_s3_data = {}".format(
            ard_location,
            s3_storage_handler.get_s3_data(ard_location),  # type: ignore
        ),
    )

    module_classification_processor(bucket, key, "aux_data", args.max_tasks)

    logger.info("EXIT !")
