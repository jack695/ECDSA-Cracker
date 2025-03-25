import pandera as pa

UNCRACKED_COMMON_COLUMNS = {
    "r": pa.Column(object),
    "s": pa.Column(object),
    "h": pa.Column(object),
    "pubkey": pa.Column(str),
    "sig_id": pa.Column(str),
    "block_timestamp": pa.Column("datetime64[ms, UTC]", coerce=True),
}

CRACKED_COMMON_COLUMNS = {
    "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]", coerce=True),
    "vulnerability_source": pa.Column(str),
    "lineage": pa.Column(list),
}

UncrackedSignaturesSchema = pa.DataFrameSchema({**UNCRACKED_COMMON_COLUMNS})

CrackedSignaturesSchema = pa.DataFrameSchema(
    {"pubkey": pa.Column(str), "privkey": pa.Column(object), **CRACKED_COMMON_COLUMNS}
)

KnownNoncesSchema = pa.DataFrameSchema(
    {"r": pa.Column(object), "nonce": pa.Column(object), **CRACKED_COMMON_COLUMNS}
)

UncrackedCyclingSignaturesSchema = pa.DataFrameSchema(
    {
        "cycle_id": pa.Column("int64"),
        **UNCRACKED_COMMON_COLUMNS,
    }
)


def check_output_format(schema):
    def decorator(function):
        def wrapper(*args, **kwargs):
            df = function(*args, **kwargs)
            if len(df.index) > 0:
                df = df[schema.columns.keys()]
                schema.validate(df)
            return df

        return wrapper

    return decorator


def check_input_format(schema, nth_arg):
    def decorator(function):
        def wrapper(*args, **kwargs):
            df = args[nth_arg]
            if len(df.index) > 0:
                df = df[schema.columns.keys()]
                schema.validate(df)
            ret = function(*args[:nth_arg], df, *args[nth_arg + 1 :], **kwargs)
            return ret

        return wrapper

    return decorator
