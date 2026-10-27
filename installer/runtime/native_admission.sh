#!/bin/sh
set -eu
umask 077
exec /usr/bin/ruby /usr/share/openclash/lan-center-admission-supervisor.rb
