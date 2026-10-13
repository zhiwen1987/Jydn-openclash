#!/usr/bin/env ruby
# Add the node capability hook to OpenClash's custom overwrite script once.

unless ARGV.length == 1
  warn "usage: install_node_capability_hook.rb OPENCLASH_CUSTOM_OVERWRITE"
  exit 2
end

path = ARGV.fetch(0)
content = File.read(path, encoding: "UTF-8")
start_marker = "# >>> Jydn isolated node capability probe >>>"
end_marker = "# <<< Jydn isolated node capability probe <<<"

anchor = "# >>> Jydn AMD Radeon direct DNS >>>"
raise "OpenClash overwrite anchor is missing" unless content.include?(anchor)

block = <<~SH.chomp
  #{start_marker}
  /etc/openclash/custom/jydn_node_capability_hook.sh "$CONFIG_FILE" || \
    printf '%s [警告] Jydn node capability disabled after hook failure\\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> /tmp/openclash.log
  #{end_marker}
SH

updated = if content.include?(start_marker)
  pattern = /#{Regexp.escape(start_marker)}.*?#{Regexp.escape(end_marker)}/m
  content.sub(pattern, block)
else
  content.sub(anchor, "#{block}\n\n#{anchor}")
end

if updated == content
  puts "node_capability_overwrite_hook=present"
  exit 0
end

temporary = "#{path}.tmp.#{$$}"
File.open(temporary, "w", 0o755) { |file| file.write(updated) }
File.rename(temporary, path)
puts "node_capability_overwrite_hook=updated"
