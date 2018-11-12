#!/bin/bash

CLONE_DIR=target/jetty-alpn-wiki

mkdir target

git clone git@github.com:jetty-project/jetty-alpn.wiki.git $CLONE_DIR

WIKI_FILE=$CLONE_DIR/ALPN-Boot-Versions.md

echo "OpenJDK version | ALPN version" > $WIKI_FILE
echo "--------------- | -------------" >> $WIKI_FILE

cat version_mapping.properties | sed -e "s/=/ | /" >> $WIKI_FILE

pushd $CLONE_DIR
git commit -m "Updating Wiki: ALPN-Boot-Versions.md" ALPN-Boot-Versions.md
git push origin master
popd

rm $CLONE_DIR

