import argparse

# import glob
# import json
import logging
import os
import signal
import sys
import time

from prefect import flow, get_run_logger
from prefect_dask.task_runners import DaskTaskRunner

sys.path.insert(0, os.path.join(os.path.dirname(sys.path[0]), "../", "rs-server/src/"))
import s3_storage_handler  # noqa


def os_sig_handler(signalNumber, frame):
    print("Received the signal {}".format(signalNumber))

    if (
        signalNumber == signal.SIGTERM
        or signalNumber == signal.SIGINT
        or signalNumber == signal.SIGQUIT
        or signalNumber == signal.SIGABRT
    ):
        print(
            "Interruption caught ! The node will be probably terminated. \
SIGTERM will be sent to all running processes and exit",
        )
        s3_storage_handler.aws_terminating_node_notice = True
        return
    print("The signal received is not SIGTERM/SIGINT/SIGQUIT/SIGABRT. Doing nothing...")


@flow(task_runner=DaskTaskRunner())
def s3_handler(action, list_with_files, bucket, prefix, max_runners=10):
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


if __name__ == "__main__":
    log_folder = "./upload_files/"
    os.makedirs(log_folder, exist_ok=True)
    logFormatter = logging.Formatter("[%(asctime)-20s] [%(name)-10s] [%(levelname)-6s] %(message)s")
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setLevel(logging.DEBUG)
    consoleHandler.setFormatter(logFormatter)
    log_filename = log_folder + "s3_handler_" + time.strftime("%Y%m%d_%H%M%S") + ".log"
    fileHandler = logging.FileHandler(log_filename)
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(logFormatter)

    logger = logging.getLogger("upload_files")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    logger.propagate = False

    logger.addHandler(consoleHandler)

    logger.addHandler(fileHandler)

    signal.signal(signal.SIGINT, os_sig_handler)
    signal.signal(signal.SIGQUIT, os_sig_handler)
    signal.signal(signal.SIGILL, os_sig_handler)
    signal.signal(signal.SIGTRAP, os_sig_handler)
    signal.signal(signal.SIGABRT, os_sig_handler)
    signal.signal(signal.SIGSEGV, os_sig_handler)
    signal.signal(signal.SIGTERM, os_sig_handler)

    parser = argparse.ArgumentParser(
        description="It ploads / downloads files and / or directories to / from a s3 bucket",
    )
    parser.add_argument("-b", "--bucket", type=str, required=True, help="Bucket to work with")
    parser.add_argument(
        "-p",
        "--prefix",
        type=str,
        required=True,
        help="S3 prefix (root where all the files will be uploaded)",
    )
    parser.add_argument(
        "-f",
        "--files",
        type=str,
        required=True,
        help="File with information for objects to be uploaded / downloaded. \
The structure of the file: each line is either a full path to a local file / directory\
 for upload case or a full s3 path to a s3 key (file or directory) for download case",
    )
    parser.add_argument("-s", "--secret-file", type=str, required=True, help="File with the secrets")
    parser.add_argument(
        "-a",
        "--action",
        type=str,
        required=True,
        help="Action to perform. Possible values: 'd' (for download) or 'u' (for upload)",
        choices={"d", "u"},
    )
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

    list_with_files = []
    with open(args.files, "r") as files:
        lines = files.readlines()
        for line in lines:
            list_with_files.append(line.strip())

    if args.action == "d":
        list_with_files = s3_storage_handler.files_to_be_downloaded(  # type: ignore
            args.bucket,
            list_with_files,
            logger,
        )
        action = "download"
    elif args.action == "u":
        list_with_files = s3_storage_handler.files_to_be_uploaded(list_with_files, logger)  # type: ignore
        action = "upload"
    else:
        # impossible, but for the code sake
        logger.error("Action may be 'd' or 'u'")
        sys.exit(-1)

    if len(list_with_files) > 0:
        s3_handler(action, list_with_files, args.bucket, args.prefix, args.max_tasks)
    else:
        logger.info("No file has been found for {}".format("downloading" if args.action == "d" else "uploading"))

    logger.info("EXIT !")
