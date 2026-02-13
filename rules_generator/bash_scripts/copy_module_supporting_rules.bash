grep -rl "get_module_equivalent_key" ./assets | while read file; do
    dest="./module_support$(echo "$file" | sed 's/^\.\/assets//')"
    mkdir -p "$(dirname "$dest")";  cp "$file" "$dest"
done
