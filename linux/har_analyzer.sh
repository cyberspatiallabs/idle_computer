grep -Eo "https?://\S+?" accu.har | awk -F '/' '{print $3}' | grep  -v '\"' | sort | uniq -c | sort -rn | column -t
