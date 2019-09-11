#!/bin/sh
# Create source distribution of scgi package
set -e
TMP=$(mktemp -d --tmpdir=.)
git archive master | tar -x -C $TMP
./git-changelog > $TMP/CHANGES.txt
rm $TMP/dist.sh $TMP/git-changelog
(cd $TMP && python3 setup.py sdist)
cp -v $TMP/dist/* dist
rm -r $TMP
