# log4jjndilookupremove
 A simple script to remove Log4J JndiLookup.class from jars in given directory.
 This script can be used to temporarily resolve the CVE-2021-45046 and CVE-2021-44228, until the application can be repackaged with a proper Log4J version.
 
 ## Usage
 On Linux or other \*nix system just run this script in the directory you want to scan, or add the target directory as first parameter:
 ```
 $. scanjars.sh
 ```
 or
 ```
 $. scanjars.sh <target_dir>
 ```
## Dependencies
* bash
* zip
* unzip
