#!/bin/bash
##
## Generates the private and public certificate used for signing 
## and verifying the JWT.

openssl genrsa -out private-key.pem 4096
openssl rsa -in private-key.pem -pubout -out public-key.pem