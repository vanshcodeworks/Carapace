#!/usr/bin/env python3
"""P2 runtime matrix: run agent-typical workloads through the sandbox.

This is the honest answer to "does the seccomp/Landlock/rootfs recipe work
for real runtimes, not just /bin/sh and python3?" (docs/agent/UNVERIFIED.md
R1.2). Every case asserts real output from the real Tier 1 sandbox.

Run inside the Linux dev environment:

    CARGO_TARGET_DIR=$HOME/.cache/carapace-target cargo build -p carapace-cli
    CARA=$CARGO_TARGET_DIR/debug/cara python3 scripts/runtime-matrix.py

The script bridges itself through `systemd-run --user --scope` when cgroup
delegation is not in the current session (WSL), and skips cleanly when
`cara doctor` says the environment cannot isolate. Optional runtimes
(node, gcc, rustc) are skipped when absent.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

NL = chr(10)
SKIP = 0

# WSL: re-exec inside the user cgroup slice (delegation requirement).
if os.path.exists("/proc/self/cgroup"):
    cg = open("/proc/self/cgroup").read()
    if f"user.slice/user-{os.getuid()}.slice" not in cg and os.path.exists(
        "/usr/bin/systemd-run"
    ):
        os.execvp(
            "systemd-run",
            [
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "python3",
                os.path.abspath(__file__),
            ],
        )

CARA = os.environ.get(
    "CARA", os.path.expanduser("~/.cache/carapace-target/debug/cara")
)


def have(path):
    return os.path.exists(path)


# Fail-closed gate: refusing to report a matrix on an environment that
# cannot isolate is more honest than a wall of red. `cara doctor` exits 4
# when a required check fails (its JSON report has no derived "ready" key).
doctor = subprocess.run([CARA, "doctor", "--json"], capture_output=True)
if doctor.returncode != 0:
    print("SKIP runtime matrix: environment not Tier 1 ready (cara doctor)")
    sys.exit(0)


def run(argv, timeout=60):
    p = subprocess.run([CARA, "run", "--json", "--"] + argv,
                       capture_output=True, timeout=timeout)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"exit_code": None, "stdout": "", "stderr": p.stderr.decode(errors="replace")}


results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"))


def skip(name, why):
    global SKIP
    SKIP += 1
    print(f"SKIP {name}  [{why}]")


# --- bash + coreutils ---
cases = [
    ("bash-pipes-sort", ["/bin/bash", "-c", 'printf "b\na\nc\n" | sort | head -2'], lambda r: "a\nb" in r["stdout"]),
    ("bash-awk-sed", ["/bin/bash", "-c", 'echo "hello 123" | sed "s/123/456/" | awk \'{print $2}\''], lambda r: "456" in r["stdout"]),
    ("bash-find-grep", ["/bin/bash", "-c", 'find /usr/share/doc -name "*.txt*" 2>/dev/null | head -3 | wc -l'], lambda r: r["stdout"].strip() not in ("", "0")),
    ("bash-date-expr", ["/bin/bash", "-c", 'test $(date +%Y) -ge 2024 && expr 3 ' + chr(42) + ' 4 = 12'], lambda r: r["exit_code"] == 0),
]
for name, argv, verify in cases:
    r = run(argv)
    check(name, r["exit_code"] == 0 and verify(r), r["stderr"][:120])

# --- python stdlib ---
pycases = [
    ("py-json-re", ["import json,re,hashlib",
                    "assert json.loads('{\"a\": 1}')['a'] == 1",
                    "assert re.match('[0-9]+', '123').group() == '123'",
                    "print(hashlib.sha256(b'x').hexdigest()[:8])"], "2d711642"),
    ("py-subprocess", ["import subprocess",
                       "out = subprocess.run(['/bin/echo', 'sub-ok'], capture_output=True)",
                       "print(out.stdout.decode().strip())"], "sub-ok"),
    ("py-sqlite3", ["import sqlite3",
                    "c = sqlite3.connect(':memory:')",
                    "c.execute('create table t(x)')",
                    "c.execute('insert into t values (42)')",
                    "print(c.execute('select x from t').fetchone()[0])"], "42"),
    ("py-multiprocessing", ["import multiprocessing as mp",
                            "print(mp.Pool(2).map(abs, [-1, -2]) == [1, 2])"], "True"),
    ("py-ssl-no-network", ["import ssl", "ssl.create_default_context()", "print('ssl-ok')"], "ssl-ok"),
    ("py-threads", ["import threading",
                    "results = []",
                    "def work(): results.append(1)",
                    "ts = [threading.Thread(target=work) for _ in range(4)]",
                    "[t.start() for t in ts]; [t.join() for t in ts]",
                    "print('threads', len(results))"], "threads 4"),
    ("py-concurrent-futures", ["from concurrent.futures import ThreadPoolExecutor",
                               "with ThreadPoolExecutor(2) as ex:",
                               "    print(list(ex.map(lambda x: x * 2, [1, 2])))"], "[2, 4]"),
]
for name, lines, expect in pycases:
    code = "\n".join(lines)
    r = run(["/usr/bin/python3", "-c", code])
    ok = r["exit_code"] == 0 and expect in r["stdout"]
    check(name, ok, (r["stderr"][:150] or r["stdout"][:80]))

# --- node json (inline, no file needed) ---
if have("/usr/bin/node"):
    r = run(["/usr/bin/node", "-e", 'console.log(JSON.parse(JSON.stringify({a:42})).a)'])
    check("node-json", r["exit_code"] == 0 and "42" in r["stdout"],
          (r["stderr"][:150] or r["stdout"][:80]))
else:
    skip("node-json", "no /usr/bin/node")

# --- file-payload section: shared rw dir via policy (gcc, node worker,
# rust binary). The sandbox has its own /tmp and cannot see the host's,
# so payloads that need files must live in a bound read-write dir.
workdir = tempfile.mkdtemp(prefix="cara-rtm-")
policy = os.path.join(workdir, "policy.toml")
with open(policy, "w") as f:
    f.write("[filesystem]" + NL + f'read_write = ["{workdir}"]' + NL)


def run_policy(argv):
    # --policy goes BEFORE the `--` separator.
    p2 = subprocess.run([CARA, "run", "--policy", policy, "--json", "--"] + argv,
                        capture_output=True, timeout=60)
    try:
        return json.loads(p2.stdout)
    except json.JSONDecodeError:
        return {"exit_code": None, "stdout": "", "stderr": p2.stderr.decode(errors="replace")}


try:
    # node worker_threads (code file; eval-mode quoting is unworkable)
    if have("/usr/bin/node"):
        worker_js = os.path.join(workdir, "worker.js")
        main_js = os.path.join(workdir, "main.js")
        with open(worker_js, "w") as f:
            f.write('const { parentPort } = require("worker_threads");' + NL
                    + 'parentPort.postMessage("worker-ok");' + NL)
        with open(main_js, "w") as f:
            f.write('const { Worker } = require("worker_threads");' + NL
                    + 'const w = new Worker(' + json.dumps(worker_js) + ');' + NL
                    + 'w.on("message", (m) => { console.log(m); process.exit(0); });' + NL
                    + 'w.on("error", (e) => { console.error(String(e).slice(0, 120)); process.exit(1); });' + NL)
        r = run_policy(["/usr/bin/node", main_js])
        check("node-worker", r["exit_code"] == 0 and "worker-ok" in r["stdout"],
              (r["stderr"][:150] or r["stdout"][:80]))
    else:
        skip("node-worker", "no /usr/bin/node")

    # gcc compile-and-run (sources + binary in the rw dir)
    if have("/usr/bin/gcc"):
        src = os.path.join(workdir, "m.c")
        out = os.path.join(workdir, "m")
        with open(src, "w") as f:
            f.write('#include <stdio.h>' + NL + 'int main(void){puts("gcc-ok");return 0;}' + NL)
        r = run_policy(["/bin/bash", "-c", f"gcc {src} -o {out} && {out}"])
        check("gcc-compile-run", r["exit_code"] == 0 and "gcc-ok" in r["stdout"],
              r["stderr"][:150])
    else:
        skip("gcc-compile-run", "no /usr/bin/gcc")

    # rust binary: built on the host with rustc, run inside via the same bind
    rs = os.path.join(workdir, "rtm.rs")
    with open(rs, "w") as f:
        f.write('fn main() { println!("rust-ok"); }' + NL)
    rust_bin = os.path.join(workdir, "rust-bin")
    try:
        rc = subprocess.run(["rustc", "-O", "-o", rust_bin, rs], capture_output=True)
    except FileNotFoundError:
        rc = None
    if os.path.exists(rust_bin):
        r = run_policy([rust_bin])
        check("rust-binary", r["exit_code"] == 0 and "rust-ok" in r["stdout"],
              r["stderr"][:120])
    else:
        skip("rust-binary", "no rustc")
finally:
    shutil.rmtree(workdir, ignore_errors=True)

p = sum(1 for _, ok, _ in results if ok)
f = sum(1 for _, ok, _ in results if not ok)
print(f"=== runtime matrix: {p} passed, {f} failed, {SKIP} skipped")
sys.exit(1 if f else 0)
