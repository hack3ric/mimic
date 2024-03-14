#!/bin/bash

find src -type f -regex '.*\.[ch]' | xargs xgettext -k_ -kN_
