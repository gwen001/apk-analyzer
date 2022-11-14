# apk-analyzer

Analyze an extracted APK archive and generate a HTML report.

## Install

pip3 install -r requirements.txt

## Usage

```
$ python3 apk-analyzer.py -h
usage: apk-analyzer.py [-h] [-d DIRECTORY] [-t TERM] [-c] [-m MOD]

options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        source directory
  -t TERM, --term TERM  term referencing the editor
  -c, --command         display commands to run
  -m MOD, --mod MOD     mod to run
```


# apk-downloader

Mass download APKs listed in `package_names.txt`.

## Install

pip3 install -r requirements.txt

## Usage

```
$ python3 apk-downloader.py
```
