import pandera as pa

UncrackedSignaturesSchema = pa.DataFrameSchema(
    {
        "block_timestamp": pa.Column("datetime64[ms, UTC]"),
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "sig_id": pa.Column(str),
    }
)

CrackedSignaturesSchema = pa.DataFrameSchema(
    {
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "pubkey": pa.Column(str),
        "privkey": pa.Column(object),
        "vulnerability_source": pa.Column(str),
        "sig_ids": pa.Column(list),
    }
)

KnownNoncesSchema = pa.DataFrameSchema(
    {
        "r": pa.Column(object),
        "nonce": pa.Column(object),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "vulnerability_source": pa.Column(str),
        "sig_ids": pa.Column(list),
    }
)

CrackableSignaturesSchema = pa.DataFrameSchema(
    {
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "nonce": pa.Column(object),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "sig_id": pa.Column(str),
    }
)

CrackableNoncesSchema = pa.DataFrameSchema(
    {
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "privkey": pa.Column(object),
        "sig_id": pa.Column(str),
    }
)

UncrackedCyclingSignaturesSchema = pa.DataFrameSchema(
    {
        "block_timestamp": pa.Column("datetime64[ms, UTC]"),
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "cycle_id": pa.Column("int64"),
        "sig_id": pa.Column(str),
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
            function(*args[:nth_arg], df, *args[nth_arg + 1 :], **kwargs)
            return df

        return wrapper

    return decorator
