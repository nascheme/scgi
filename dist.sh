#!/bin/sh

git log | grep -v ^commit > CHANGES.txt
python setup.py sdist
rm CHANGES.txt MANIFEST
