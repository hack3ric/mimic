#!/bin/bash
set -e

quilt pop || :

_ver=`dpkg-parsechangelog --show-field Version`
_ver="${_ver/-*}"

_ref=$(git stash create)
[ -n "$_ref" ] || _ref=HEAD

echo $_ref

git archive --format=tar.gz --prefix="mimic-$_ver/" -v "$_ref" > "../mimic_$_ver.orig.tar.gz"
