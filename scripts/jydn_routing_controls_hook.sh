#!/bin/sh
set -eu
ruby /etc/openclash/custom/jydn_routing_controls.rb "$1" \
  /etc/openclash/custom/jydn_stable_menu_catalog.json \
  /etc/openclash/custom/jydn_routing_controls.json
