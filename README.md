# wauth - 4-eye-principe authentictaion PAM Module

In some cases we need to ensure that some actions are executed with a whitness.

Configuration in PAM:

To let the whitness user provide his username simply add the following line to the pam.d/common-auth
> auth requisite wauth.so

if we want to enforce a specific user
> auth requisite wauth.so username

## Compiling

### Linux ( tested on Debian Trixie )
Just start the make file, which will compile and link the module
```
gcc -fPIC -fno-stack-protector -c auth.c
ld -x --shared -lcrypt -o /lib/x86_64-linux-gnu/security/wauth.so auth.o
```

## In Action
```
kisauto@b8f472a7691f:~$ sudo su - root
Whithness login: whitness
Whitness password: 
[sudo] password for kisauto:
root@b8f472a7691f:~#
```
