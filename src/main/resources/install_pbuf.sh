#! /bin/bash

# Shamelessly stolen from StackOverflow
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

protoc -I=${dir} --java_out=${dir}/../java/ ${dir}/panda_messages.proto --experimental_allow_proto3_optional
