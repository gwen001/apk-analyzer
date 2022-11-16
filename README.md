# apk-analyzer
<p align="left">
    <img src="https://img.shields.io/badge/python-v3-blue" alt="python badge">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license badge">
    <a href="https://twitter.com/intent/tweet?text=https%3a%2f%2fgithub.com%2fgwen001%2fgitpillage%2f" target="_blank"><img src="https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Fgithub.com%2Fgwen001%2Fapk-analyzer" alt="twitter badge"></a>
</p>

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
