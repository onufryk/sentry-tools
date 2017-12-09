# Script to parse Sentry issues and events and analyze source code of stack traces

## Prerequisited

- python 2.7
- pip
- virtualenv

## Installation

```
virtualenv .virtualenv
source .virtualenv/bin/activate
pip install pip --upgrade
pip install -r requirements.txt
```

## Help

```
python sentry.py --help
```

## Usage

```
usage: sentry.py [-h] [--token TOKEN] [--no-line-numbers]
                 [--trim-level {1,2,3,4}] [--debug]
                 query

Script to collect stacktraces related to a sentry error

positional arguments:
  query                 String to search list of issues

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN         Sentry API token
  --no-line-numbers     Omit line numbers in analysis
  --trim-level {1,2,3,4}
                        How many last lines of stacktrace to process
  --debug               Verbose output mode
```
