{ pkgs }:
# Publishes verified Hydra artifacts without rebuilding them. A revision is
# eligible once both the CLI and GPU channels succeeded for it; images go to
# ghcr.io under an immutable commit tag, then the floating backend tags.
pkgs.writeShellApplication {
  name = "hellas-publish";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.curl
    pkgs.gh
    pkgs.gnugrep
    pkgs.jq
    pkgs.skopeo
  ];
  text = ''
    hydra=''${HYDRA_URL:-https://hydra.hellas.ai}
    cache=''${HELLAS_CACHE_URL:-https://cache.hellas.ai}
    cache_key=''${HELLAS_CACHE_KEY:-cache.hellas.ai-1:PYolh95U/Ms5fKE+NQTcNZUHyEv4QikaNocg9I9iy0g=}
    registry=''${HELLAS_IMAGE_REPOSITORY:-ghcr.io/hellas-ai/hellas}
    repository=''${HELLAS_GITHUB_REPOSITORY:-hellas-ai/hellas}
    dry_run=0
    revision=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --dry-run) dry_run=1 ;;
        --revision) revision=$2; shift ;;
        *) echo "usage: hellas-publish [--dry-run] [--revision SHA]" >&2; exit 2 ;;
      esac
      shift
    done

    if [ -n "''${GHCR_TOKEN:-}" ]; then
      skopeo login "''${registry%%/*}" --username "''${GHCR_USER:?}" --password-stdin <<< "$GHCR_TOKEN"
    fi

    api() { curl -fsS -H 'Accept: application/json' "$hydra$1"; }
    run() {
      if [ "$dry_run" = 1 ]; then echo "dry run: $*"; else "$@"; fi
    }

    # "revision eval" for each evaluation whose channel job succeeded, newest first.
    green() {
      api "/jobset/hellas/$1/evals" | jq -r '.evals[] | "\(.jobsetevalinputs.hellasSrc.revision) \(.id)"' |
        while read -r rev id; do
          if api "/eval/$id/builds" | jq -e 'any(.[]; .job == "channel" and .finished == 1 and .buildstatus == 0)' > /dev/null; then
            echo "$rev $id"
          fi
        done
    }
    cli=$(green hellas-cli)
    gpu=$(green hellas-gpu)
    floating=0
    if [ -z "$revision" ]; then
      # The newest CLI-green revision that the GPU channel also passed.
      revision=$(while read -r rev _; do
        if grep -q "^$rev " <<< "$gpu"; then echo "$rev"; break; fi
      done <<< "$cli")
      floating=1
    fi
    if [ -z "$revision" ]; then
      # A scheduled run with nothing eligible has nothing to do.
      echo "no revision has both a green CLI and GPU channel yet"
      exit 0
    fi
    cli_eval=$(grep "^$revision " <<< "$cli" | head -1 | cut -d' ' -f2)
    gpu_eval=$(grep "^$revision " <<< "$gpu" | head -1 | cut -d' ' -f2)
    if [ -z "$cli_eval" ] || [ -z "$gpu_eval" ]; then
      echo "$revision lacks a green CLI or GPU channel among recent evaluations" >&2
      exit 1
    fi
    echo "revision $revision (CLI eval $cli_eval, GPU eval $gpu_eval)"

    builds=$(jq -s 'add' <(api "/eval/$cli_eval/builds") <(api "/eval/$gpu_eval/builds"))
    output() {
      jq -er --arg job "$1" '[.[] | select(.job == $job and .buildstatus == 0)][0].buildoutputs.out.path' <<< "$builds"
    }
    version=$(jq -er '[.[] | select(.job == "x86_64-linux.validation")][0].nixname | ltrimstr("hellas-cli-validation-")' <<< "$builds")

    # Fetching from the cache checks its signature; each artifact then
    # checks its own archive against the SHA256SUMS built beside it.
    fetch() {
      local path
      path=$(output "$1")
      nix copy --from "$cache" --option trusted-public-keys "$cache_key" "$path" >&2
      (cd "$path" && sha256sum --check --quiet SHA256SUMS) >&2
      echo "$path"
    }

    config_digest() { skopeo inspect --raw --config "$1" | sha256sum | cut -d' ' -f1; }
    digests=""
    for backend in network:x86_64-linux.artifacts.network-image hip:x86_64-linux.artifacts.hip-image cuda:x86_64-linux.artifacts.cuda-image; do
      name=''${backend%%:*}
      path=$(fetch "''${backend#*:}")
      archive="docker-archive:$path/hellas-$name-$revision.tar.gz"
      tag="$registry:sha-$revision-$name"
      local_config=$(config_digest "$archive")
      if remote_config=$(config_digest "docker://$tag" 2> /dev/null); then
        if [ "$remote_config" != "$local_config" ]; then
          echo "$tag already names different content" >&2
          exit 1
        fi
        echo "$tag already published"
      else
        run skopeo copy "$archive" "docker://$tag"
      fi
      if [ "$dry_run" = 1 ]; then
        digest="(unpublished)"
      else
        digest=$(skopeo inspect --format '{{.Digest}}' "docker://$tag")
      fi
      digests+="- \`$tag\`: \`$digest\`"$'\n'
      if [ "$floating" = 1 ]; then
        aliases=("$name")
        if [ "$name" = network ]; then aliases+=(latest); fi
        for alias in "''${aliases[@]}"; do
          run skopeo copy "docker://$tag" "docker://$registry:$alias"
        done
      fi
    done

    release="v$version-''${revision:0:12}"
    assets=()
    staged=$(mktemp -d --tmpdir="''${RUNNER_TEMP:-$PWD}" hellas-publish.XXXXXX)
    trap 'rm -rf "$staged"' EXIT
    sums=$staged/SHA256SUMS
    for job in x86_64-linux.artifacts.portable-x86_64 x86_64-linux.artifacts.portable-aarch64 aarch64-darwin.artifacts.portable-aarch64 x86_64-linux.artifacts.wasm; do
      path=$(fetch "$job")
      cat "$path/SHA256SUMS" >> "$sums"
      assets+=("$path"/*.tar.gz)
      case "$job" in
        *.portable-*) ;;
        *) continue ;;
      esac
      archive=$(basename "$path"/*.tar.gz "-$revision.tar.gz").tar.gz
      cp "$path"/*.tar.gz "$staged/$archive"
      (cd "$staged" && sha256sum "$archive" > "$archive.sha256")
      cat "$staged/$archive.sha256" >> "$sums"
      assets+=("$staged/$archive" "$staged/$archive.sha256")
    done
    installer=$(fetch x86_64-linux.artifacts.installer)
    cat "$installer/SHA256SUMS" >> "$sums"
    assets+=("$installer/install.sh")
    if existing=$(gh release download "$release" --repo "$repository" --pattern SHA256SUMS --output - 2> /dev/null); then
      if [ "$existing" != "$(cat "$sums")" ]; then
        echo "release $release already names different archives" >&2
        exit 1
      fi
      echo "release $release already published"
      exit 0
    fi
    notes="Hydra-built artifacts of $revision (CLI eval $cli_eval, GPU eval $gpu_eval). Images are CI-built, not hardware-qualified."$'\n\n'"$digests"
    run gh release create "$release" --repo "$repository" --target "$revision" --title "Hellas $version-''${revision:0:12}" --notes "$notes" "''${assets[@]}" "$staged/SHA256SUMS"
  '';
}
