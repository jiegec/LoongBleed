#!/bin/sh
g++ -std=c++11 -O2 -march=native -pthread -o loongbleed_poc loongbleed_poc.cpp
./loongbleed_poc $@
