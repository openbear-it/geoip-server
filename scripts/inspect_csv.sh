#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <csv-file>

Prints information about the CSV/GZCSV file: detected delimiter, header,
first 10 data rows and up to 5 distinct samples per column (from first 10 rows).

Examples:
  $0 ip2location.csv
  $0 dbip-city/dbip-city-ipv4.csv.gz
EOF
}

if [[ ${#} -ne 1 ]]; then
  usage
  exit 1
fi

file=$1
if [[ ! -f "$file" ]]; then
  echo "File not found: $file" >&2
  exit 2
fi

# reader function (handles .gz)
reader() {
  if [[ "$file" == *.gz ]]; then
    gzip -dc -- "$file"
  else
    cat -- "$file"
  fi
}

# Read first line to detect delimiter
firstline=$(reader | head -n1 || true)
if [[ -z "$firstline" ]]; then
  echo "Empty file or failed to read: $file" >&2
  exit 3
fi

delimiter=','
if printf '%s' "$firstline" | grep -q $'\t'; then
  delimiter=$'\t'
  delim_name="TAB"
elif printf '%s' "$firstline" | grep -q ';'; then
  delimiter=';'
  delim_name="SEMICOLON"
elif printf '%s' "$firstline" | grep -q '|'; then
  delimiter='|'
  delim_name="PIPE"
else
  delimiter=','
  delim_name="COMMA"
fi

# Create tmp file: header + first 10 data rows
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
reader | head -n 11 > "$tmp"

header=$(head -n1 "$tmp")
# split header into array
IFS=$delimiter read -r -a cols <<< "$header"
num_cols=${#cols[@]}

echo "File: $file"
echo "Detected delimiter: $delim_name"
echo "Columns: $num_cols"
echo "Header: $header"

echo "\nFirst up to 10 data rows (after header):"
tail -n +2 "$tmp" | nl -ba -w2 -s': '

echo "\nColumn samples (up to 5 distinct values from first 10 rows):"
for ((i=1;i<=num_cols;i++)); do
  # awk field uses -F with the chosen delimiter
  samples=$(tail -n +2 "$tmp" | awk -F"$delimiter" -v c=$i '{gsub(/^ +| +$/,"", $c); if($c!="") print $c}' | awk '!seen[$0]++' | head -n5 | paste -sd "; " -)
  colname=${cols[$((i-1))]}
  if [[ -z "$samples" ]]; then
    samples="(empty)"
  fi
  printf "  %2d: %s => %s\n" "$i" "$colname" "$samples"
done

# show a preview of types (best-effort: numeric vs string) from the sample rows
echo "\nColumn type hints (based on samples):"
for ((i=1;i<=num_cols;i++)); do
  typ=$(tail -n +2 "$tmp" | awk -F"$delimiter" -v c=$i '{gsub(/^ +| +$/,"", $c); if($c!="") print $c}' | head -n10 | awk '
  function isnnum(s){ return (s ~ /^-?[0-9]+(\.[0-9]+)?$/) }
  { if(isnnum($0)) n++ ; else s++ }
  END { if(n>0 && s==0) print "numeric"; else if(n>0 && s>0) print "mixed"; else print "string" }'
  colname=${cols[$((i-1))]}
  printf "  %2d: %s => %s\n" "$i" "$colname" "$typ"
done

exit 0
