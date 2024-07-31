# ECDSA Signatures Extraction

The current scope of this project is limited to collecting ECDSA signatures from UTXO blockchains.
Those signatures could be used later to detect repeated nonces or to evaluate lattice based attacks performance over them.

NOTE: This code is a poorly written PoC. I don't plan spending much time cleaning it as this project is a one shot.

## All chains but bch
```
python3 -m signatures.extract_signatures -t local/data/dash -o local/signatures/dash -n 1
```
## Bch

See Jupyter notebook [extract_bch_signatures.ipynb](signatures/extract_bch_signatures.ipynb)

## Improvement Suggestion
Update the client code of the different blockchains directly to populate the db of signatures.