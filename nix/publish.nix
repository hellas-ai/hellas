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
    pkgs.nix
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
    lane=""
    verify_cache=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --dry-run) dry_run=1 ;;
        --verify-cache) verify_cache=1 ;;
        --revision) revision=''${2:?missing revision}; shift ;;
        --lane) lane=''${2:?missing lane}; shift ;;
        *) echo "usage: hellas-publish [--dry-run] [--revision SHA] [--lane LANE] [--verify-cache]" >&2; exit 2 ;;
      esac
      shift
    done

    if [ -n "$revision" ] && ! [[ "$revision" =~ ^[0-9a-f]{40}$ ]]; then
      echo "invalid revision" >&2; exit 2
    fi
    api() { curl -fsS -H 'Accept: application/json' "$hydra$1"; }

    if [ "$verify_cache" = 1 ]; then
      case "$lane" in
        nix-thin) package=default; output_name=thin ;;
        l1) package="cli-validator"; output_name=l1 ;;
        cuda|hip) package="cli-$lane"; output_name=$package ;;
        *) echo "--verify-cache requires a native package lane" >&2; exit 2 ;;
      esac
    fi

    if [ -n "$lane" ]; then
      if [ "$dry_run" != 1 ]; then
        echo "lane verification requires --dry-run" >&2
        exit 2
      fi
      case "$lane" in
        nix-thin) component=cli; systems=(x86_64-linux aarch64-linux aarch64-darwin) ;;
        standalone) component=cli; systems=(x86_64-linux aarch64-darwin) ;;
        network|wasm) component=cli; systems=(x86_64-linux) ;;
        cuda|hip) component=gpu; systems=(x86_64-linux) ;;
        l1) component=consensus; systems=(x86_64-linux) ;;
        *) echo "unknown release lane: $lane" >&2; exit 2 ;;
      esac
      gates=$(printf '%s\n' "''${systems[@]}" | jq -R --arg lane "$lane" '. + ".promotionGates." + $lane' | jq -s .)
      evaluations=$(api "/jobset/hellas/hellas-$component/evals")
      while read -r candidate id; do
        builds=$(api "/eval/$id/builds")
        if jq -e --argjson gates "$gates" '
          . as $builds
          | all($gates[]; . as $gate | any($builds[];
              .job == $gate and .finished == 1 and .buildstatus == 0))
        ' <<< "$builds" > /dev/null; then
          printf '%s revision %s (Hydra eval %s)\n' "$lane" "$candidate" "$id"
          if [ "$verify_cache" = 1 ]; then
            fresh=$(mktemp -d)
            trap 'rm -rf "$fresh"' EXIT
            store_uri="local?root=$fresh"
            for system in "''${systems[@]}"; do
              output=$(jq -er --arg job "$system.promotionOutputs.$output_name" '
                first(.[] | select(.job == $job and .finished == 1 and .buildstatus == 0))
                | .buildoutputs.out.path
              ' <<< "$builds")
              exact=$(nix eval --accept-flake-config --raw "github:$repository/$candidate#packages.$system.$package.outPath")
              if [ "$output" != "$exact" ]; then
                echo "$system Hydra output differs from the exact flake package" >&2
                exit 1
              fi
              nix copy --from "$cache" --to "$store_uri" --option builders "" --option max-jobs 0 \
                --option require-sigs true --option trusted-public-keys "$cache_key" "$output"
              nix store verify --store "$store_uri" --recursive --sigs-needed 1 \
                --option trusted-public-keys "$cache_key" "$output"
            done
          fi
          exit 0
        fi
      done < <(jq -r --arg revision "$revision" '
        .evals[]
        | select(.jobsetevalinputs.hellasSrc.revision | type == "string" and test("^[0-9a-f]{40}$"))
        | select($revision == "" or .jobsetevalinputs.hellasSrc.revision == $revision)
        | "\(.jobsetevalinputs.hellasSrc.revision) \(.id)"
      ' <<< "$evaluations")
      echo "no eligible $lane revision''${revision:+ for $revision} among recent evaluations" >&2
      exit 1
    fi

    if [ -n "''${GHCR_TOKEN:-}" ]; then
      skopeo login "''${registry%%/*}" --username "''${GHCR_USER:?}" --password-stdin <<< "$GHCR_TOKEN"
    fi
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
      # Nothing is eligible yet.
      echo "no revision has both a green CLI and GPU channel yet"
      exit 0
    fi
    cli_eval=$(grep "^$revision " <<< "$cli" | head -1 | cut -d' ' -f2 || true)
    gpu_eval=$(grep "^$revision " <<< "$gpu" | head -1 | cut -d' ' -f2 || true)
    if [ -z "$cli_eval" ] || [ -z "$gpu_eval" ]; then
      echo "$revision lacks a green CLI or GPU channel among recent evaluations" >&2
      exit 1
    fi
    echo "revision $revision (CLI eval $cli_eval, GPU eval $gpu_eval)"

    cli_builds=$(api "/eval/$cli_eval/builds")
    builds=$(jq -s 'add' <(echo "$cli_builds") <(api "/eval/$gpu_eval/builds"))
    output() {
      jq -er --arg job "$1" '[.[] | select(.job == $job and .buildstatus == 0)][0].buildoutputs.out.path // error("missing successful artifact job: \($job)")' <<< "$builds"
    }
    # Both components have a job named x86_64-linux.release. Read CLI metadata
    # from its own evaluation, then verify the signed store output and identity.
    manifest=$(jq -er '[.[] | select(.job == "x86_64-linux.release" and .finished == 1 and .buildstatus == 0)][0].buildoutputs.out.path // error("missing CLI release manifest")' <<< "$cli_builds")
    nix copy --from "$cache" --option trusted-public-keys "$cache_key" "$manifest"
    version=$(jq -er --arg revision "$revision" '
      select(.component == "cli" and .system == "x86_64-linux" and .revision == $revision)
      | .version | select(type == "string" and test("^[0-9]+[.][0-9]+[.][0-9]+([-+][0-9A-Za-z.-]+)?$"))
    ' "$manifest/release.json")
    image_jobs=(network:x86_64-linux.artifacts.network-image hip:x86_64-linux.artifacts.hip-image cuda:x86_64-linux.artifacts.cuda-image)
    archive_jobs=(x86_64-linux.artifacts.portable-x86_64 x86_64-linux.artifacts.portable-aarch64 aarch64-darwin.artifacts.portable-aarch64 x86_64-linux.artifacts.wasm)
    # Resolve the complete release before changing any published tags.
    for job in "''${image_jobs[@]#*:}" "''${archive_jobs[@]}" x86_64-linux.artifacts.installer; do
      output "$job" > /dev/null
    done

    # Fetching from the cache checks its signature; each artifact then
    # checks its own archive against the SHA256SUMS built beside it.
    fetch() {
      local path
      path=$(output "$1") || return
      nix copy --from "$cache" --option trusted-public-keys "$cache_key" "$path" >&2 || return
      (cd "$path" && sha256sum --check --quiet SHA256SUMS) >&2 || return
      echo "$path"
    }

    config_digest() { skopeo inspect --raw --config "$1" | sha256sum | cut -d' ' -f1; }
    digests=""
    for backend in "''${image_jobs[@]}"; do
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
    for job in "''${archive_jobs[@]}"; do
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
