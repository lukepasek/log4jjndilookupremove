#!/bin/bash

remove=0
COLOR_RED=31
COLOR_GREEN=32
COLOR_YELLOW=33
COLOR_GRAY=37

function color() {
    local c=$1
    local b=0
    local n=0
    shift
    if [ "$1" == "-n" ]; then
        shift
        n=1
    fi
    if [ "$1" == "-b" ]; then
        shift
        b=1
    fi
    if [ "$n" -eq 1 ]; then
        echo -n -e '\033['$b';'$c'm'$@'\033[0m'
    else
        echo -e '\033['$b';'$c'm'$@'\033[0m'
    fi
}

function green() {
    color ${COLOR_GREEN} $@
}

function red() {
    color ${COLOR_RED} $@
}

function yellow() {
    color ${COLOR_YELLOW} $@
}

function gray() {
    color${COLOR_GRAY} $@
}

function fat_jar_ident() {
    for c in $(seq 1 $jar_level); do
        echo -n "   "
    done
}

JNDI_MANAGER_PATCH="allowedJndiProtocols"
JNDI_MANAGER_PATCH_216="log4j2.enableJndi"
JNDI_MANAGER_PATCH_217="isJndiLookupEnabled"
JNDI_LOOKUP_V21="LOOKUP"
JNDI_LOOKUP_V212="JNDI is not supported"

function test_lookup_class() {
    local jar=$1
    local cls=$2

    unzip -p "$jar" "$cls" | strings | grep -q $JNDI_LOOKUP_V21
    if [ $? -eq 0 ]; then
        echo "2.1+"
        return 210
    fi
    unzip -p "$jar" "$cls" | strings | grep -q -a $JNDI_LOOKUP_V212
    if [ $? -eq 0 ]; then
        echo "2.1.2 (BACKPORT)"
        return 212
    fi
    echo "UNKNOWN/2.0"
    return 200
}

function test_manager_class() {
    local jar=$1
    local cls=$2

    unzip -p "$jar" "$cls" | strings | grep -q $JNDI_MANAGER_PATCH
    if [ $? -eq 0 ]; then
        unzip -p "$jar" "$cls" | strings | grep -q $JNDI_MANAGER_PATCH_216
        if [ $? -eq 0 ]; then
            echo "2.16"
            return 216
        fi
        echo "2.15"
        return 215
    fi
    unzip -p "$jar" "$cls" | strings | grep -q -a $JNDI_MANAGER_PATCH_216
    if [ $? -eq 0 ]; then
        unzip -p "$jar" "$cls" | strings | grep -q $JNDI_MANAGER_PATCH_217
        if [ $? -eq 0 ]; then
            echo "2.17"
            return 217
        fi
        echo "2.12"
        return 212
    fi
    echo "UNKNOWN/2.0"
    return 200
}

function log4j_shell_status() {
    if [ $2 -eq 9999 ]; then
        echo "OK"
        return 0
    fi
    if [ $1 -ge 217 -a $2 -ge 210 ]; then
        echo "OK"
        return 0
    fi
    if [ $1 -eq 215 -a $2 -ge 210 ]; then
        echo "PARTIAL"
        return 1
    fi
    echo "BAD"
    return 1
}


yellow "### Log4J JndiLookup.class scanner/remover"

for arg in "$@"; do
    if [ "$arg" == "--remove" ]; then
        shift
        remove=1
        yellow "### Removing JndiLookup.class from archives and directories!!!"
    fi
    if [ "$arg" == "-v" ]; then
        shift
        verbose="yes"
        yellow "### Verbose mode - reporting all Jar and War files"
    fi
done

if [ -n "$1" ]; then
    scan_dir=$(realpath "$1")
else
    scan_dir=$(realpath "$(pwd)")
    yellow "### Work dir not specified - using current dir: $scan_dir"
fi

LOOKUP_CLASS_NAME="core/lookup/JndiLookup.class"
MANAGER_CLASS_NAME="core/net/JndiManager.class"

# LOOKUP_CLASS_NAME="org/apache/logging/log4j/core/lookup/JndiLookup.class"
# MANAGER_CLASS_NAME="org/apache/logging/log4j/core/net/JndiManager.class"

jarcnt=0
warcnt=0
removed=0
IFS=$'\n'
TMP_DIR=/tmp/log4jjndilookupremove
mkdir -p $TMP_DIR
cd $TMP_DIR
jar_level=0

function scanjars() {
    if [ -z "$1" ]; then
        red "Not scanning undefined directory!"
        exit -1
    fi
    local dir=$(realpath "$1")
    # echo "### Scanning for class in jar files in $dir"
    # echo "Finding jar and war files in $dir"
    local cnt=0
    for f in $(find $dir -type f -name '*.jar' -o -type f -name '*.war'); do
        local fat_jar="no"
        local log4j="no"
        local class_removed="no"
        local have_manager_cls="no"
        local have_lookup_cls="no"
        local lookup_cls_version="???"
        local lookup_cls_version_nr=0
        local manager_cls_version="???"
        local manager_cls_version_nr=0

        jarcnt=$(($jarcnt+1))
        if [ "$verbose" == "yes" ]; then
            if [ -z "$2" ]; then
                green -n $f
            else
                fat_jar_ident
                green -n "[$2]:"${f##${dir}}
            fi
        fi
        for j in $(unzip -l "$f"|awk '{if ($4) print $4;}'); do
            case "$j" in
                *$LOOKUP_CLASS_NAME)
                    log4j="yes"
                    have_lookup_cls="yes"
                    # test_lookup_class $f $j
                    lookup_cls_version=$(test_lookup_class "$f" "$j")
                    lookup_cls_version_nr=$?
                    if [ $remove -eq 1 ]; then
                        zip -q -d "$j" "$LOOKUP_CLASS_NAME" && \
                        class_removed="yes"
                    fi
                ;;
                *$MANAGER_CLASS_NAME)
                    log4j="yes"
                    have_manager_cls="yes"
                    manager_cls_version=$(test_manager_class "$f" "$j")
                    manager_cls_version_nr=$?
                ;;
                *.jar)
                    fat_jar="yes"
                ;;
                *.war)
                    fat_jar="yes"
                ;;
            esac
        done
        if [ "$fat_jar" == "yes" ]; then
            if [ "$verbose" == "yes" ]; then
                yellow " - Fat jar or war (level $jar_level)"
            fi
            if [ -f "$f" ]; then
                fatjar "$f"
            else
                scanclasses "$f"
            fi
        elif [ "$log4j" == "no" ]; then
            if [ "$verbose" == "yes" ]; then
                green -b " - CLEAN"
            fi
        elif [ "$log4j" == "yes" ]; then
            if [ "$verbose" == "yes" ]; then
                yellow -b " - Log4J found"
            fi
            cnt=$(($cnt+1))
        fi
        if [ "$log4j" == "yes" ]; then
            local version=$(unzip -p "$f" "META-INF/MANIFEST.MF" |grep "Implementation-Version" | awk '{print $2}')
            red -b "$f: "
            yellow -n "   Log4J version (from manifest): "
            yellow -b "$version"
            if [ "$have_manager_cls" == "yes" ]; then
                yellow -n "   JndiManager class found, detected version: "
                yellow -b "$manager_cls_version"
            else
                yellow "   JndiManager class removed/not found"
            fi
            if [ "$have_lookup_cls" == "yes" ]; then
                yellow -n "   JndiLookup class found, detected version: "
                yellow -b "$lookup_cls_version"
            else
                yellow "   JndiLookup class removed/not found"
                lookup_cls_version_nr=99999
            fi
            yellow -n "   Status: "
            local status=$(log4j_shell_status $manager_cls_version_nr $lookup_cls_version_nr)
            case $status in
                "OK") green -b "OK/CLEAN";;
                "PARTIAL") yellow -b "PARTIAL";;
                "BAD") red -b "VULNERABLE";;
                *) red -b "UNKNOWN";;
            esac
        fi
    done
    return $cnt
}

function scanclasses() {
    if [ -z "$1" ]; then
        red "Not scanning undefined directory"
        exit -1
    fi
    local dir=$(realpath "$1")
    # echo "### Scanning for class in directory $dir"
    find "$dir" -type f -name 'JndiLookup.class' | while read f; do
        case "$f" in
            *$LOOKUP_CLASS_NAME)
                red "Class JndiLookup located: $f"
                if [ $remove -eq 1 ]; then
                    rm -f $f && \
                    removed=$(($removed+1)) && \
                    green "Class file removed" || \
                    yellow "Class file NOT removed from directory!"
                else
                    removed=$(($removed+1)) && \
                    yellow "Class file NOT removed"
                fi
            ;;
            *)
                if [ "$verbose" == "yes" ]; then
                    yellow "Not removing file $f: its not the file you are looking for..."
                fi
            ;;
        esac
    done
}

function fatjar() {
    if [ -z "$1" ]; then
        red "Not scanning undefined file"
        exit 1
    fi
    if ! [ -f "$1" ]; then
        red "Not scanning $1 - its not a file"
        exit 1
    fi
    jar_level=$(($jar_level+1))
    local fat_jar_file=$1
    local name=$(basename $fat_jar_file)
    case $name in
        *.jar) jar_tmp_dir=$TMP_DIR/fatjar_${jar_level}_$(date +%s)/${name%%.jar};;
        *.war) jar_tmp_dir=$TMP_DIR/war_${jar_level}_$(date +%s)/${name%%.war};;
        *.zip) jar_tmp_dir=$TMP_DIR/zip_${jar_level}_$(date +%s)/${name%%.zip};;
        *) red "File format not supported!" && exit 1;;
    esac

    # echo "Unpacking archive to $jar_tmp_dir and descending..."
    local pwd=$(pwd)
    test -d "$jar_tmp_dir" && red "------- error: destination temp dir exists: $jar_tmp_dir" && exit 1
    mkdir -p "$jar_tmp_dir"
    cd "$jar_tmp_dir"
    unzip -q -o -d "$jar_tmp_dir" "$fat_jar_file"
    local fat_jar_removed=0
    scanjars . "$(basename $fat_jar_file)"
    fat_jar_removed=$?
    scanclasses .
    if [ $fat_jar_removed -gt 0 ]; then
        echo "$LOOKUP_CLASS_NAME removed" > LOG4JSHELL.txt
        echo -n "Archive modified, repacking $(pwd) ... "
        if [ $remove -eq 1 ]; then
            zip -r "new_${fat_jar_file}" . && green "Archive repacked" || red "Archive repacking error!"
        else
            yellow "Archive NOT repacked"
        fi
        ls -l "$jar_tmp_dir"
        unzip -l "$fat_jar_file"
    else
        if [ $jar_level -eq 1 ]; then
            if [ "$verbose" == "yes" ]; then
                green -n "${fat_jar_file}"
                green -b " - CLEAN"
            fi
        fi
    fi
    cd "$pwd"
    rm -Rf "$jar_tmp_dir"
    jar_level=$(($jar_level-1))
}

if [ -f "$scan_dir" ]; then
    green -n $scan_dir
    yellow " - Fat jar or war (level $jar_level)"
    fatjar "$scan_dir"
else
    yellow "### Finding class, jar, and war files in $scan_dir"
    scanjars "$scan_dir"
    scanclasses "$scan_dir"
fi

yellow "### Scan finished."
