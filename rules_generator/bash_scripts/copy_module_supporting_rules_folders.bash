grep -rl "get_module_equivalent_key" ./assets | while read file; do
    dest="./module_support$(echo "$file" | sed 's/^\.\/assets//' | sed 's|/[^/]*$||')"
    mkdir -p "$(dirname "$dest")";  cp -r "$(echo "$file" | sed 's|/[^/]*$||')" "$dest"
done
