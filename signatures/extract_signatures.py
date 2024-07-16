"""
 # @ Author: Vincent Jacquot
 # @ Create Time: 2024-07-16 14:19:55
 # @ Description: Script to extract the public keys, signatures and message digest from a UTXO chain.
 """

import argparse
import csv
import glob
from itertools import repeat
import logging
import multiprocessing as mp
import os
import json
from .utils import format_fields, buildCTransaction
from bitcoin.core.script import CScript
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript, EvalScript
from bitcoin.core import x
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


def save_data(data: list, output_dir: str, file_id: int):
    with open(os.path.join(output_dir, f"signatures_{file_id:05x}.csv"), "w") as f:
        csv_writer = csv.writer(
            f, delimiter=",", quotechar="\\", quoting=csv.QUOTE_MINIMAL
        )
        csv_writer.writerows(data)

    df = pd.DataFrame(
        data,
        columns=[
            "transaction_hash",
            "input_index",
            "r",
            "s",
            "message digest",
            "pubkey",
        ],
    )
    table = pa.Table.from_pandas(df)
    out_file = os.path.join(output_dir, f"signatures_{file_id:05x}.parquet")
    pq.write_table(table, out_file)


def write_signatures(output_dir: str, queue: mp.Queue, record_per_file: int):

    data, file_id, record = [], 0, queue.get()
    while record:
        data.append(record)
        if len(data) >= record_per_file:
            save_data(data, output_dir, file_id)
            data, file_id = [], file_id + 1
        record = queue.get()

    save_data(data, output_dir, file_id)


def job(file: str, queue: mp.Queue, log_folder: str):
    logger = logging.getLogger(f"{__name__}_{os.getpid()}")
    logging.basicConfig(
        filename=os.path.join(log_folder, f"logs_{os.getpid()}.log"), level=logging.INFO
    )
    logger.info(f"Job started for file {file}.")

    with open(file) as f:
        for n, line in enumerate(f):
            try:
                if not n % 1000:
                    logger.info(f"{n} lines parsed.")
                raw_tx = json.loads(line)
                format_fields(raw_tx)
                tx = buildCTransaction(raw_tx, queue)

                prevouts = {
                    i: CScript(x(raw_tx["inputs"][i]["spent_script_hex"]))
                    for i in range(len(tx.vin))
                }

                for i in range(len(tx.vin)):
                    flags = {SCRIPT_VERIFY_P2SH}

                    VerifyScript(tx.vin[i].scriptSig, prevouts[i], tx, i, flags=flags)

                for twinwit in tx.wit.vtxinwit:
                    EvalScript(
                        twinwit.scriptWitness.stack,
                        CScript(x("ac")),
                        tx,
                        i,
                        flags=flags,
                    )

            except Exception as e:
                logger.error(f"Process failed at line: {line}: {e}")

    logger.info(f"Job finished  for file {file}.")


def extract_sigs(tx_folder: str, output_folder: str, n_workers: int):
    tx_files = glob.glob(os.path.join(f"{tx_folder}", "*.json"))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    log_folder = os.path.join(output_folder, "logs")
    if not os.path.isdir(log_folder):
        os.mkdir(log_folder)
    queue = mp.Manager().Queue(maxsize=10**4)

    # Start to write data on disk
    p = mp.Process(
        target=write_signatures,
        args=(output_folder, queue, 10**6),
    )
    p.start()

    # Start the extraction
    with mp.Pool(n_workers) as p:
        p.starmap(job, zip(tx_files, repeat(queue), repeat(log_folder)))

    # Signals the writer that all records have been read
    queue.put(None)

    # Wait
    p.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process the input folder.")
    parser.add_argument(
        "-t",
        "--transactions",
        help="Folder containing the transactions.",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output_folder",
        help="Output folder.",
        required=True,
    )
    parser.add_argument(
        "-n",
        "--n_workers",
        help="Number of workers.",
        default=16,
        type=int,
        required=False,
    )
    args = vars(parser.parse_args())
    extract_sigs(args["transactions"], args["output_folder"], args["n_workers"])
