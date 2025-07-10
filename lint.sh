#!/usr/bin/env bash

ruff format src *.py
ruff check --fix --output-format=full src tests *.py
