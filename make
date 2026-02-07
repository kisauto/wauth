#!/bin/bash

gcc -fPIC -fno-stack-protector -c auth.c

ld -x --shared -lcrypt -o /lib/x86_64-linux-gnu/security/wauth.so auth.o
ls -la /lib/x86_64-linux-gnu/security/wauth.so

rm auth.o

