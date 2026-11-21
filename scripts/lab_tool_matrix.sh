#!/bin/sh
# Limited authorized lab matrix for HostSec OpenSCAP adapters.
# Not invoked by make check or CI. Only evaluate chroots created on this box.
# oscap-chroot requires privilege to enter a chroot; this script uses sudo
# locally and never passes --fetch-remote-resources or --remediate.
set -eu

ROOT="${HOSTSEC_MATRIX_ROOT:-/tmp/hostsec-tool-lab/chroots}"
OUT="${HOSTSEC_MATRIX_LOGDIR:-/tmp/hostsec-tool-lab/matrix/summaries}"
mkdir -p "$OUT"

eval_one() {
  os_id="$1"
  chroot="$2"
  content="$3"
  rule="$4"
  if [ ! -d "$chroot" ]; then
    echo "skip $os_id: chroot $chroot is missing" >&2
    return 0
  fi
  work="$OUT/$os_id"
  mkdir -p "$work"
  results="$work/openscap-results.xml"
  echo "evaluating $os_id with $content rule $rule"
  sudo oscap-chroot "$chroot" xccdf eval --rule "$rule" --results "$results" "$content"
  # Do not keep raw ARF/XCCDF results in git; callers should extract the
  # rule result and delete the XML if it may contain system characteristics.
}

eval_one debian-12 "$ROOT/debian12" \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml \
  xccdf_org.ssgproject.content_rule_prefer_64bit_os

eval_one ubuntu-24.04 "$ROOT/ubuntu2404" \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml \
  xccdf_org.ssgproject.content_rule_package_prelink_removed
