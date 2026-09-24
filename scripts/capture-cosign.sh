#!/usr/bin/env bash
# Captures the real cosign vectors the image verifier and its
# consumers' discovery are proven on (testdata/NOTICE.md): a throwaway
# image pushed to a registry, signed keyless by cosign twice — its
# default sigstore bundle referrer, and the legacy simple-signing
# layer under the signature tag — then every carrier fetched as the
# registry serves it, with the registry's referrers answer, the
# fallback referrers tag, the trusted root and signing configuration
# in force at signing time, and cosign's own verdicts as the expected
# values. Runs under GitHub Actions (.github/workflows/capture-cosign.yml),
# where the ambient OIDC token is the signing identity; the same
# script runs anywhere cosign can obtain an identity.
#
# Inputs, as environment: IMAGE (the repository to push to, no tag),
# OUT (the directory to write), and optionally IDENTITY and ISSUER
# (the certificate identity and OIDC issuer cosign verify is held to;
# absent, they are read from cosign's own verdict on the legacy
# carrier and recorded), SIGNING_CONFIG (a signing configuration file
# for the bundle sign in place of the one TUF serves as the default —
# that one names no Rekor v2 log; TUF's target
# signing_config_rekor_v2.v0.2.json names one), and
# DIGEST, which resumes a capture whose image is already pushed and
# signed — signing needs a human at a browser, the fetches do not —
# at the fetch of the trusted root. Needs cosign v3, crane, curl and
# jq, and registry credentials in the docker config.
set -euo pipefail

: "${IMAGE:?the repository to push to}"
: "${OUT:?the output directory}"
if [ -n "${IDENTITY:-}" ] || [ -n "${ISSUER:-}" ]; then
  : "${IDENTITY:?IDENTITY and ISSUER are given together}" "${ISSUER:?IDENTITY and ISSUER are given together}"
fi
mkdir -p "$OUT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "capture: $*" >&2; exit 1; }

# tagState records whether a tag exists, and its manifest where it
# does: <tag> <file stem>.
tagState() {
  if crane manifest "$IMAGE:$1" > "$2.manifest.json" 2> "$tmp/tag.err"; then
    echo "tag $1 present"
  else
    rm -f "$2.manifest.json"
    cp "$tmp/tag.err" "$2.absent"
    echo "tag $1 absent"
  fi
}

# verifyAs records cosign's verdict on one carrier form under the
# given identity: <form> <file stem> <identity> <issuer>. cosign's
# verify of the bundle form falls back to the legacy carrier where it
# finds no bundle, so a bundle verdict is held to the bundle's own
# claim type.
verifyAs() {
  cosign verify --new-bundle-format="$1" --certificate-identity "$3" --certificate-oidc-issuer "$4" \
    --output json "$IMAGE@$digest" > "$2.json" 2> "$2.log" || fail "cosign verify ($2) failed: $(cat "$2.log")"
  if [ "$1" = true ]; then
    jq -e '.[0].critical.type == "https://sigstore.dev/cosign/sign/v1"' "$2.json" > /dev/null \
      || fail "cosign verify ($2) verified no bundle: $(jq -c '.[0].critical.type' "$2.json")"
  fi
}

if [ -z "${DIGEST:-}" ]; then
  # A minimal OCI image: one layer holding one file.
  mkdir -p "$tmp/layer"
  printf 'gitprov cosign capture\n' > "$tmp/layer/capture.txt"
  tar -C "$tmp/layer" -cf "$tmp/layer.tar" capture.txt
  tag="capture-$(date -u +%Y%m%dT%H%M%SZ)"
  crane append --oci-empty-base -f "$tmp/layer.tar" -t "$IMAGE:$tag" > /dev/null
  digest=$(crane digest "$IMAGE:$tag")
  hex=${digest#sha256:}
  echo "pushed $IMAGE:$tag = $digest"
  echo "$digest" > "$OUT/digest"
  echo "$tag" > "$OUT/tag"

  # The two signatures: cosign's default carrier, the bundle referrer,
  # under the signing configuration TUF serves; then the legacy
  # carrier, the simple-signing layer under the tag, which cosign v3
  # writes only without a signing configuration (the default Rekor v1
  # log). Between them, the tag state: whether the default sign
  # attaches the legacy tag or the fallback referrers tag beside the
  # bundle; and cosign's verdict on the bundle, before the legacy
  # carrier exists — its verify falls back to the legacy tag where it
  # finds no bundle, and a verdict recorded now can only be the
  # bundle's.
  cosign version --json > "$OUT/cosign-version.json" 2> /dev/null || fail "cosign version --json failed"
  if [ -n "${SIGNING_CONFIG:-}" ]; then
    cp "$SIGNING_CONFIG" "$OUT/signing-config-given.json"
    cosign sign --yes --new-bundle-format=true --signing-config "$SIGNING_CONFIG" "$IMAGE@$digest" 2>&1 | tee "$OUT/sign-bundle.log"
  else
    cosign sign --yes --new-bundle-format=true "$IMAGE@$digest" 2>&1 | tee "$OUT/sign-bundle.log"
  fi
  tagState "sha256-$hex.sig" "$OUT/after-bundle-sign.signature-tag"
  tagState "sha256-$hex" "$OUT/after-bundle-sign.referrers-fallback-tag"
  if [ -n "${IDENTITY:-}" ]; then
    verifyAs true "$OUT/verify-bundle" "$IDENTITY" "$ISSUER"
  fi
  cosign sign --yes --new-bundle-format=false --use-signing-config=false "$IMAGE@$digest" 2>&1 | tee "$OUT/sign-legacy.log"
else
  digest=$DIGEST
  hex=${digest#sha256:}
  tag=$(cat "$OUT/tag" 2>/dev/null || echo "")
  echo "resuming at $IMAGE@$digest"
fi

# The trusted root and signing configuration cosign fetched through
# TUF for these signatures: the keys the captures verify against, in
# sigstore-go's cache layout — a mirror directory over targets, which
# cosign 3 reads; an older cosign's flat targets directory beside it
# is not the layout in use. Exactly one of each, or the capture is
# ambiguous.
tufRoot=${TUF_ROOT:-$HOME/.sigstore/root}
mapfile -t roots < <(find "$tufRoot" -mindepth 3 -path '*/targets/trusted_root.json')
[ "${#roots[@]}" -eq 1 ] || fail "${#roots[@]} trusted_root.json under a mirror of $tufRoot: ${roots[*]:-none}"
cp "${roots[0]}" "$OUT/trusted-root.json"
mapfile -t configs < <(find "$tufRoot" -mindepth 3 -path '*/targets/signing_config*.json')
[ "${#configs[@]}" -ge 1 ] || fail "no signing_config*.json under a mirror of $tufRoot"
for c in "${configs[@]}"; do
  [ ! -e "$OUT/$(basename "$c")" ] || fail "two signing configurations named $(basename "$c")"
  cp "$c" "$OUT/"
done

# The registry's answers, raw: the image's manifest, the referrers
# API's index for it with the response's status and headers, the
# fallback referrers tag cosign writes where the API is absent, every
# referrer's manifest and layers, and the signature tag's manifest
# and layers.
host=${IMAGE%%/*}
repoPath=${IMAGE#*/}
challenge=$(curl -sS -o /dev/null -D - "https://$host/v2/" | tr -d '\r' | grep -i '^www-authenticate:' || true)
realm=$(sed -n 's/.*realm="\([^"]*\)".*/\1/p' <<< "$challenge")
service=$(sed -n 's/.*service="\([^"]*\)".*/\1/p' <<< "$challenge")
[ -n "$realm" ] || fail "no token realm in $host's challenge: $challenge"
auth=$(jq -r --arg h "$host" '.auths[$h].auth // empty' "${DOCKER_CONFIG:-$HOME/.docker}/config.json")
[ -n "$auth" ] || fail "no credentials for $host in the docker config"
token=$(curl -sS -H "Authorization: Basic $auth" "$realm?service=$service&scope=repository:$repoPath:pull" | jq -r '.token // .access_token // empty')
[ -n "$token" ] || fail "no pull token from $realm"

crane manifest "$IMAGE@$digest" > "$OUT/image-manifest.json"
status=$(curl -sS -H "Authorization: Bearer $token" -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -w '%{http_code}' -D "$OUT/referrers.headers" -o "$OUT/referrers.json" "https://$host/v2/$repoPath/referrers/$digest")
echo "$status" > "$OUT/referrers.status"
echo "referrers API: $status"
tagState "sha256-$hex" "$OUT/referrers-fallback-tag"

# Every referrer the registry names, by the API where it answers and
# by the fallback tag where cosign wrote one; the bundle referrer
# must be among them.
refs=()
if [ "$status" = 200 ]; then
  mapfile -t apiRefs < <(jq -r '.manifests[]?.digest' "$OUT/referrers.json")
  refs+=("${apiRefs[@]}")
fi
if [ -e "$OUT/referrers-fallback-tag.manifest.json" ]; then
  mapfile -t tagRefs < <(jq -r '.manifests[]?.digest' "$OUT/referrers-fallback-tag.manifest.json")
  refs+=("${tagRefs[@]}")
fi
[ "${#refs[@]}" -ge 1 ] || fail "no referrer named by the API ($status) or the fallback tag"
mapfile -t refs < <(printf '%s\n' "${refs[@]}" | sort -u)
fetchLayers() { # <manifest file> <stem>: the configuration and each layer's blob, in order
  local n=0 layer config
  config=$(jq -r '.config.digest // empty' "$1")
  [ -n "$config" ] || fail "$1 names no configuration"
  crane blob "$IMAGE@$config" > "$2.config.bin"
  for layer in $(jq -r '.layers[]?.digest' "$1"); do
    crane blob "$IMAGE@$layer" > "$2.layer-$n.bin"
    n=$((n + 1))
  done
  [ "$n" -ge 1 ] || fail "$1 names no layer"
}
# Files are named by the referrer's hex alone: a colon is no
# character for an uploaded artifact's path.
bundle=""
for ref in "${refs[@]}"; do
  stem="$OUT/referrer-${ref#sha256:}"
  crane manifest "$IMAGE@$ref" > "$stem.manifest.json"
  fetchLayers "$stem.manifest.json" "$stem"
  if jq -e '.artifactType == "application/vnd.dev.sigstore.bundle.v0.3+json"' "$stem.manifest.json" > /dev/null; then
    bundle="$stem.layer-0.bin"
  fi
done
[ -n "$bundle" ] || fail "no bundle referrer among ${refs[*]}"
tagState "sha256-$hex.sig" "$OUT/signature-tag"
[ -e "$OUT/signature-tag.manifest.json" ] || fail "no signature tag after the legacy sign"
fetchLayers "$OUT/signature-tag.manifest.json" "$OUT/signature-tag"

# cosign's verdict on the legacy carrier under the expected identity
# — read from cosign's own verdict where none was given, the legacy
# form's verdict naming the certificate's subject and issuer — and
# the record of what was captured: the identity, the digest, every
# referrer with its file stem, and the bundle's transparency entries
# — their log, kind, index and checkpoint origin — so a Rekor v1
# entry where v2 was expected is seen before the vectors land.
if [ -z "${IDENTITY:-}" ]; then
  cosign verify --new-bundle-format=false --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
    --output json "$IMAGE@$digest" > "$OUT/verify-legacy-any-identity.json" 2> "$OUT/verify-legacy-any-identity.log" \
    || fail "cosign verify (legacy, any identity) failed: $(cat "$OUT/verify-legacy-any-identity.log")"
  IDENTITY=$(jq -r '.[0].optional.Subject // empty' "$OUT/verify-legacy-any-identity.json")
  ISSUER=$(jq -r '.[0].optional.Issuer // empty' "$OUT/verify-legacy-any-identity.json")
  [ -n "$IDENTITY" ] && [ -n "$ISSUER" ] || fail "cosign's legacy verdict names no subject and issuer"
  echo "identity from cosign's verdict: $IDENTITY by $ISSUER"
fi
[ -e "$OUT/verify-bundle.json" ] || verifyAs true "$OUT/verify-bundle" "$IDENTITY" "$ISSUER"
verifyAs false "$OUT/verify-legacy" "$IDENTITY" "$ISSUER"
jq -n --arg image "$IMAGE" --arg tag "$tag" --arg digest "$digest" --arg identity "$IDENTITY" --arg issuer "$ISSUER" \
  --arg when "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg cosign "$(jq -r '.gitVersion // "unknown"' "$OUT/cosign-version.json" 2>/dev/null || echo unknown)" \
  --arg referrers "$status" --slurpfile bundle "$bundle" --args \
  '{image: $image, tag: $tag, digest: $digest, identity: $identity, issuer: $issuer, captured: $when, cosign: $cosign,
    referrersAPI: $referrers,
    referrers: [$ARGS.positional[] | {digest: ., file: ("referrer-" + ltrimstr("sha256:"))}],
    bundleEntries: [$bundle[0].verificationMaterial.tlogEntries[]? | {logId: .logId.keyId, kindVersion, logIndex, integratedTime,
      checkpointOrigin: ((.inclusionProof.checkpoint.envelope // "") | split("\n")[0])}],
    bundleTimestamps: ($bundle[0].verificationMaterial.timestampVerificationData.rfc3161Timestamps // [] | length)}' \
  -- "${refs[@]}" > "$OUT/capture.json"
echo "captured into $OUT:"; ls -l "$OUT"; cat "$OUT/capture.json"
