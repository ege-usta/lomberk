"""Audit export (Pro): every checkpoint with who approved it, as CSV or JSON Lines."""
import csv
import io
import json

FIELDS = ["created_at", "public_id", "status", "classification", "agent_label", "principal",
          "sql_text", "rows_affected", "approved_by", "chain_seq", "hash"]
FORMATS = {"csv": "text/csv", "jsonl": "application/x-ndjson"}


def _cell(value) -> str:
    if isinstance(value, list):
        value = "; ".join(value)
    value = "" if value is None else str(value)
    # Agent SQL is untrusted: a cell starting with = + - @ runs as a formula in Excel/Sheets.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def render(rows: list[dict], fmt: str) -> str:
    if fmt == "jsonl":
        return "".join(json.dumps({k: r[k] for k in FIELDS}, default=str) + "\n" for r in rows)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(FIELDS)
        writer.writerows([_cell(r[k]) for k in FIELDS] for r in rows)
        return buf.getvalue()
    raise ValueError(f"unknown export format {fmt!r}")
