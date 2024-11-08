#!/bin/bash
#
# Copyright (C) 2024  Luca Giacometti <samelinux@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

echo "Generating CA key"
read
openssl genrsa -des3 -out ca.key 4096

echo "Generating CA certificate"
read
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -sha256 -config caInfo.cfg

echo "Generating server key"
read
openssl genrsa -des3 -out server.key 4096

echo "Generating server signing request"
read
openssl req -new -key server.key -out server.csr -sha256 -config serverInfo.cfg

echo "Generating server certificate"
read
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -extfile serverInfo.cfg -extensions req_ext

echo "Generating server key without password"
read
openssl rsa -in server.key -out server.key.insecure
mv server.key server.key.secure
mv server.key.insecure server.key

