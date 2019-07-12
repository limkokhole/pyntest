#!/bin/sh

./blcheck -p $1 > tempfile.txt

matchedLists=$(cat tempfile.txt  | grep -w Blacklist | cut -d':' -f2 | tr '\n' ',')

tested=$(cat tempfile.txt | grep Tested | tr -s ' ' ':' | cut -d: -f2)
passed=$(cat tempfile.txt | grep Passed | tr -s ' ' ':' | cut -d: -f2)
blacklisted=$(cat tempfile.txt | grep Blacklisted | tr -s ' ' ':' | cut -d: -f2)

echo $tested:$blacklisted:$matchedLists

rm tempfile.txt
