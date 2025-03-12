#!/bin/bash
#
#This script takes in a json file and 'breaks it down' into its top level array elements.
# It assumes the json file has an array at the top level,
# It creates a 'breakdown' directory.
# then creates files containing the full json elements of each top level item.
#
# Particularly useful for parsing avi configs into more manageable chunks.

json_filename="$1"
json_file_fullpath=`realpath "$json_filename"`
base_directory=`dirname "$json_file_fullpath"`

outputdir="$base_directory"/"$json_filename-breakdown"

mkdir "$outputdir"

keys=`cat "$json_file_fullpath" | jq '(keys)? // .' | jq -cr '.[]'`

for i in $keys; do
        cat "$json_file_fullpath" | jq ".$i" > "$outputdir/$json_filename.$i.json"
done