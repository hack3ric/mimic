#!/bin/bash

find src -type f -regex '.*\.[ch]' | xargs xgettext -k_
