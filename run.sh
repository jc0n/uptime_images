#!/bin/bash

make clean all

./extract_images $1 $2

cd out/

for f in $(find . -maxdepth 1 -name "*.jpg"); do
    while [ $(jobs | wc -l) -gt 8 ]; do
        sleep 0.5;
    done
    convert -resize '40%' "$f" "${f%%jpg}png" &
done

rm -fv *.jpg
find . -maxdepth 1 -name "*.png" | \
    sort -t'.' -k1 -V | sed 's/^\.\///' | \
    awk -f ../generate_html.awk - > index.html
