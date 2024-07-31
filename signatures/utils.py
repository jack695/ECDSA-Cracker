"""
 # @ Author: Vincent Jacquot
 # @ Create Time: 2024-07-16 14:32:49
 # @ Description: A bunch of util functions to ingest TRM data.
 """

from queue import Queue
from bitcoin.core import (
    COutPoint,
    CTxIn,
    CTxInWitness,
    CTxOut,
    CTransaction,
    CTxWitness,
    x,
)

from bitcoin.core.script import CScript, CScriptWitness


def buildCTransaction(tx_json: dict, queue: Queue):
    inputs = [None] * len(tx_json["inputs"])
    witnesses = []
    for input in tx_json["inputs"]:
        if "witness" not in input["type"]:
            inputs[input["index"]] = CTxIn(
                COutPoint(
                    bytes(reversed(x(input["spent_transaction_hash"]))),
                    input["spent_output_index"],
                ),
                CScript(x(input["script_hex"])),
                input["sequence"],
                extras={"type": input["type"]},
            )
        else:
            inputs[input["index"]] = CTxIn(
                COutPoint(
                    bytes(reversed(x(input["spent_transaction_hash"]))),
                    input["spent_output_index"],
                ),
                CScript(x("")),
                input["sequence"],
                extras={"type": input["type"]},
            )

            witness_data = list(map(x, input["script_asm"].split(",")))
            witness = CTxInWitness(CScriptWitness(witness_data))
            witnesses.append(witness)
    outputs = [None] * len(tx_json["outputs"])
    for output in tx_json["outputs"]:
        outputs[int(output["index"])] = CTxOut(
            int(output["value"]), CScript(x(output["script_hex"]))
        )

    return CTransaction(
        inputs,
        outputs,
        int(tx_json["lock_time"]),
        int(tx_json["version"]),
        CTxWitness(witnesses),
        out_queue=queue,
        extras={
            "chain": tx_json["chain"],
            "transaction_hash": tx_json["transaction_hash"],
            "block_timestamp": tx_json["block_timestamp"]
        },
    )


def format_fields(tx: dict):
    if type(tx) != dict:
        return
    to_int_fields = [
        "version",
        "lock_time",
        "index",
        "value",
        "spent_output_index",
        "sequence",
    ]

    for key in tx:
        if key in to_int_fields:
            tx[key] = int(tx[key])
        elif type(tx[key]) == dict:
            format_fields(tx[key])
        elif type(tx[key]) == list:
            list(map(format_fields, tx[key]))
