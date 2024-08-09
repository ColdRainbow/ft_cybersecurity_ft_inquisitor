#!/bin/bash

# Check arp packages
arp -a

# Create test files
echo "This is a test file" > testfile.txt

# Perform FTP file transfers
ftp -a $1 <<EOF
put testfile.txt upload/testfile.txt
get upload/testfile.txt testfile_local.txt
bye
EOF
