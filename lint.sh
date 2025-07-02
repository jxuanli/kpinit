#!/usr/bin/env bash

ruff format --diff src *.py
ruff check --fix --output-format=full src *.py
