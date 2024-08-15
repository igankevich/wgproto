#!/bin/sh

. ./ci/preamble.sh

cargo +nightly miri setup
env MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test
