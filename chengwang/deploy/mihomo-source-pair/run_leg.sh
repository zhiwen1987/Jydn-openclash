#!/usr/bin/env bash
# One isolated source measurement leg. Controller tools are mounted separately
# and never supply Go package bytes or a replacement normal-contract script.
set -euo pipefail
test "$#" -eq 8
source_repo="$1"
controller_repo="$2"
out="$3"
control="$4"
goroot="$5"
source_commit="$6"
controller_commit="$7"
leg="$8"

case "$leg" in
  A) expected=a46f1b93ddec3b600fbe46e906795b84c363f848 ;;
  B) expected=b5b5fa96cadbf35ae833c618555ab82e5d70429b ;;
  *) exit 2 ;;
esac
test "$(id -u)" -eq 0
test "$source_commit" = "$expected"
[[ "$controller_commit" =~ ^[a-f0-9]{40}$ ]]
test -d "$source_repo/chengwang/vendor"
test -d "$controller_repo/chengwang/deploy/mihomo-source-pair"
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

controller="$controller_repo/chengwang/deploy/mihomo-source-pair/pair_controller.py"
checker="$controller_repo/chengwang/deploy/mihomo-source-pair/check_pair.py"
normal="$source_repo/chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh"
python3 -B "$checker" leg-script-contract --source "$source_repo" --leg "$leg"
python3 -B "$source_repo/chengwang/deploy/mihomo-capacity-profile/check_profile.py" source \
  --repo "$source_repo" --source-commit "$source_commit" --out "$control/inner-source.json"
python3 -B "$controller" inner-binding --source "$source_repo" --controller "$controller_repo" \
  --goroot "$goroot" --source-commit "$source_commit" --controller-commit "$controller_commit" \
  --leg "$leg" --out "$control/inner-binding.json"
python3 -B "$controller" inner-resource --source "$source_repo" --phase BEFORE --out "$control/inner-resource-before.json"

set +e
bash "$normal" "$source_repo" "$out" "$goroot"
leg_exit=$?
set -e

python3 -B "$controller" fsync-originals --out "$out" --receipt "$control/originals-fsync.json" \
  --source-commit "$source_commit"
python3 -B "$controller" inner-resource --source "$source_repo" --phase AFTER --out "$control/inner-resource-after.json"
exit "$leg_exit"
