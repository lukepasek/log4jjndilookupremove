#!/bin/bash
if [ -n "$1" ]; then
    workdir=$(realpath "$1")
else
    echo "### Work dir not specified - using current dir"
    workdir=$(pwd)
fi

echo "### Log4J JndiLookup.class remover running in $workdir"

CLASS_NAME="org/apache/logging/log4j/core/lookup/JndiLookup.class"
jarcnt=0
updated=0
IFS=$'\n'

for f in $(find $workdir -type f -name '*.jar'); do
    jarcnt=$(($jarcnt+1))
    unzip -l "$f" | grep -q "$CLASS_NAME"
    if [ "$?" == 0  ]; then
            echo "Class org.apache.logging.log4j.core.lookup.JndiLookup located in $f"
            zip -q -d "$f" "$CLASS_NAME" && \
            updated=$(($updated+1)) && \
            echo "Class file removed" || \
            echo "Class file NOT removed from jar!"
    fi
done

echo "### Scanned $jarcnt JAR files, removed JndiLookup.class from $updated JAR files."
