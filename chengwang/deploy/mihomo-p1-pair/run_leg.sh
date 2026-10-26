#!/usr/bin/env bash
# One isolated measurement leg. The source checkout is always exact 2eb7717;
# controller tools are mounted separately and never supply Go package bytes.
set -euo pipefail
test "$#" -eq 8
source_repo="$1"
controller_repo="$2"
out="$3"
control="$4"
goroot="$5"
source_commit="$6"
controller_commit="$7"
mode="$8"

case "$mode" in A|B) ;; *) exit 2 ;; esac
test "$(id -u)" -eq 0
test "$source_commit" = 2eb7717a7a9d32308fbb90c45b2c183c1acb53d8
[[ "$controller_commit" =~ ^[a-f0-9]{40}$ ]]
test -d "$source_repo/chengwang/vendor"
test -d "$controller_repo/chengwang/deploy/mihomo-p1-pair"
test -d "$out" && test ! -L "$out"
test -d "$control" && test ! -L "$control"
test -x "$goroot/bin/go" && test -x "$goroot/bin/gofmt"

mount --make-rprivate /
mount --bind "$source_repo" "$source_repo"
mount -o remount,bind,ro "$source_repo"
mount --bind "$controller_repo" "$controller_repo"
mount -o remount,bind,ro,nosuid,nodev "$controller_repo"
mount --bind "$goroot" "$goroot"
mount -o remount,bind,ro,nosuid,nodev "$goroot"

controller="$controller_repo/chengwang/deploy/mihomo-p1-pair/pair_controller.py"
checker="$controller_repo/chengwang/deploy/mihomo-p1-pair/check_pair.py"
baseline="$source_repo/chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh"
p1="$controller_repo/chengwang/deploy/mihomo-p1-pair/run_contracts_p1.sh"
python3 -B "$checker" script-contract --baseline "$baseline" --p1 "$p1"
python3 -B "$source_repo/chengwang/deploy/mihomo-capacity-profile/check_profile.py" source \
  --repo "$source_repo" --source-commit "$source_commit" --out "$control/inner-source.json"
python3 -B "$controller" inner-binding --source "$source_repo" --controller "$controller_repo" \
  --goroot "$goroot" --source-commit "$source_commit" --controller-commit "$controller_commit" \
  --leg "$mode" --out "$control/inner-binding.json"
python3 -B "$controller" inner-resource --source "$source_repo" --phase BEFORE --out "$control/inner-resource-before.json"

script="$baseline"
if test "$mode" = B; then script="$p1"; fi
set +e
bash "$script" "$source_repo" "$out" "$goroot"
leg_exit=$?
set -e

python3 -B "$controller" fsync-originals --out "$out" --receipt "$control/originals-fsync.json"
python3 -B "$controller" inner-resource --source "$source_repo" --phase AFTER --out "$control/inner-resource-after.json"
exit "$leg_exit"
