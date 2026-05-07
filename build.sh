#!/bin/bash

rm -rf bin
mkdir bin

rm -rf dist
mkdir dist

npm ci --silent

npm run compile

./node_modules/.bin/pkg ./package.json --options "no-warnings,max-old-space-size=4096" --targets node22-win-x64 --output bin/prefixlen-finder-win-x64

./node_modules/.bin/pkg ./package.json --options "no-warnings,max-old-space-size=4096" --targets node22-linux-x64 --output bin/prefixlen-finder-linux-x64

./node_modules/.bin/pkg ./package.json --options "no-warnings,max-old-space-size=4096" --targets node22-macos-x64 --output bin/prefixlen-finder-macos-x64

./node_modules/.bin/pkg ./package.json --options "no-warnings,max-old-space-size=4096" --targets node22-macos-arm64 --output bin/prefixlen-finder-macos-arm64

echo "--> Prefixlen finder compiled in bin/"

