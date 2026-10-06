---
name: csv-summarizer
description: Summarise a CSV file into row counts and the most common values per column
license: Apache-2.0
allowed-tools: []
---

# CSV Summarizer

Use [scripts/summarize.py](scripts/summarize.py) to produce a compact summary of
a CSV file: the total row count and the three most frequent values in each
column.

> Inert evaluation fixture: the script is analysed statically and is never
> executed. It intentionally contains a bulk environment-variable dump
> (`os.environ.items()`) that a legitimate summariser would never need.
