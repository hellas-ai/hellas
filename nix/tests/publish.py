"""Exercise the publisher with Hydra/cache/registry fixtures; never publish."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def mock(command, args):
    root = Path(os.environ["PUBLISH_FIXTURES"])
    with (root / "calls").open("a") as log:
        log.write(json.dumps([command, *args]) + "\n")
    if command == "curl":
        print((root / args[-1].removeprefix("https://fixture/").replace("/", "_")).read_text())
    elif command == "nix":
        if args[0] == "eval":
            print(os.environ["EXACT_OUTPUT"])
            return 0
        if args[:2] == ["store", "verify"]:
            assert args[args.index("--sigs-needed") + 1] == "1", args
            return 0
        assert args[0] == "copy", args
        if os.environ.get("REJECT_CACHE") == "1":
            return 1
        assert Path(args[-1]).is_dir(), args
    elif command == "skopeo":
        assert args[:3] == ["inspect", "--raw", "--config"], args
        if args[-1].startswith("docker://"):
            return 1
        print('{"architecture":"amd64"}')
    elif command == "gh":
        assert args[:2] == ["release", "download"], args
        return 1
    else:
        raise AssertionError(command)
    return 0


def test(publisher):
    root = Path(os.environ["TMPDIR"]) / "publisher"
    root.mkdir()
    os.environ["PUBLISH_FIXTURES"] = str(root)
    os.environ["HYDRA_URL"] = "https://fixture"
    revision = "a" * 40

    def write(name, value):
        (root / name).write_text(json.dumps(value))

    def job(name, path=None):
        result = {"job": name, "finished": 1, "buildstatus": 0}
        if path:
            result["buildoutputs"] = {"out": {"path": str(path)}}
        return result

    def artifact(label, filename):
        path = root / label
        path.mkdir()
        data = label.encode()
        (path / filename).write_bytes(data)
        (path / "SHA256SUMS").write_text(f"{hashlib.sha256(data).hexdigest()}  {filename}\n")
        return path

    cli_manifest = root / "cli-manifest"
    gpu_manifest = root / "gpu-manifest"
    cli_manifest.mkdir()
    gpu_manifest.mkdir()
    metadata = {"version": "1.2.3", "component": "cli", "system": "x86_64-linux", "revision": revision}
    (cli_manifest / "release.json").write_text(json.dumps(metadata))
    (gpu_manifest / "release.json").write_text(json.dumps({**metadata, "version": "9.9.9", "component": "gpu"}))
    cli = [job("channel"), job("x86_64-linux.release", cli_manifest)]
    gpu = [job("channel"), job("x86_64-linux.release", gpu_manifest)]
    for backend in ("network", "cuda", "hip"):
        path = artifact(backend, f"hellas-{backend}-{revision}.tar.gz")
        (cli if backend == "network" else gpu).append(job(f"x86_64-linux.artifacts.{backend}-image", path))
    for system, label in (("x86_64-linux", "portable-x86_64"), ("x86_64-linux", "portable-aarch64"),
                          ("aarch64-darwin", "portable-aarch64"), ("x86_64-linux", "wasm")):
        name = f"{system}-{label}"
        path = artifact(name, f"hellas-{name}-{revision}.tar.gz")
        cli.append(job(f"{system}.artifacts.{label}", path))
    cli.append(job("x86_64-linux.artifacts.installer", artifact("installer", "install.sh")))
    for component, eid, builds in (("cli", 1, cli), ("gpu", 2, gpu)):
        write(f"jobset_hellas_hellas-{component}_evals", {
            "evals": [{"id": eid, "jobsetevalinputs": {"hellasSrc": {"revision": revision}}}]})
        write(f"eval_{eid}_builds", builds)

    def run(success):
        (root / "calls").write_text("")
        result = subprocess.run([publisher, "--dry-run", "--revision", revision], text=True, capture_output=True)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
        assert any(call[0] == "nix" and call[-1] == str(cli_manifest) for call in calls), calls
        if success:
            assert f"gh release create v1.2.3-{revision[:12]}" in result.stdout, result.stdout
            assert "v9.9.9" not in result.stdout
        else:
            assert not any(call[0] in ("gh", "skopeo") for call in calls), calls

    # There is deliberately no validation job or derivation-name version.
    run(True)
    for field, value in (("revision", "b" * 40), ("component", "gpu"),
                         ("system", "aarch64-linux"), ("version", None)):
        (cli_manifest / "release.json").write_text(json.dumps({**metadata, field: value}))
        run(False)
    (cli_manifest / "release.json").write_text(json.dumps(metadata))
    os.environ["REJECT_CACHE"] = "1"
    run(False)
    print("Publisher uses signed CLI manifest metadata and rejects mismatches before publication")

    newer = "b" * 40
    write("jobset_hellas_hellas-gpu_evals", {
        "evals": [
            {"id": 3, "jobsetevalinputs": {"hellasSrc": {"revision": newer}}},
            {"id": 2, "jobsetevalinputs": {"hellasSrc": {"revision": revision}}},
        ],
    })
    cuda_output = root / "cuda"
    write("eval_3_builds", [
        job("x86_64-linux.promotionGates.cuda"),
        job("x86_64-linux.promotionOutputs.cli-cuda", cuda_output),
        {**job("x86_64-linux.promotionGates.hip"), "finished": 0, "buildstatus": None},
    ])
    write("eval_2_builds", [job("x86_64-linux.promotionGates.hip")])

    def verify_lane(lane, *arguments):
        (root / "calls").write_text("")
        result = subprocess.run(
            [publisher, "--dry-run", "--lane", lane, *arguments], text=True, capture_output=True
        )
        calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
        assert all(call[0] == "curl" and "hellas-cli" not in call[-1] for call in calls), calls
        return result

    for lane, expected, eid in (("cuda", newer, 3), ("hip", revision, 2)):
        result = verify_lane(lane)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"{lane} revision {expected} (Hydra eval {eid})"
    result = verify_lane("hip", "--revision", newer)
    assert result.returncode == 1 and "no eligible hip revision" in result.stderr, result

    args = [publisher, "--dry-run", "--lane", "cuda", "--verify-cache"]
    os.environ.pop("REJECT_CACHE")
    os.environ["EXACT_OUTPUT"] = str(cuda_output)
    (root / "calls").write_text("")
    result = subprocess.run(args, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
    copy = next(call for call in calls if call[:2] == ["nix", "copy"])
    assert copy[copy.index("--to") + 1].startswith("local?root=")
    assert ["--option", "builders", ""] == copy[copy.index("builders") - 1:copy.index("builders") + 2]
    assert any(call[:3] == ["nix", "store", "verify"] for call in calls)
    os.environ["EXACT_OUTPUT"] = str(root / "hip")
    (root / "calls").write_text("")
    result = subprocess.run(args, text=True, capture_output=True)
    assert result.returncode == 1 and "differs from the exact flake package" in result.stderr, result
    assert not any(
        json.loads(line)[:2] == ["nix", "copy"] for line in (root / "calls").read_text().splitlines()
    )



if sys.argv[1] == "mock":
    sys.exit(mock(sys.argv[2], sys.argv[3:]))
test(sys.argv[2])
