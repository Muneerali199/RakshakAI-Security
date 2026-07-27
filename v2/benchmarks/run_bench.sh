#!/usr/bin/env bash
# Wrapper to run benchmark comparison using the correct Python env
cd /teamspace/studios/this_studio/v2/benchmarks
export PYTHONNOUSERSITE=1
export PYTHONUNBUFFERED=1
/home/zeus/miniconda3/bin/python3 run_comparison.py "$@"
