"""Build the pinned disposable MTProto + Stop Go overlay; never edit source."""
import difflib
import hashlib
import json
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parent
PAYLOADS = {
    "internal/dataplane/nodecheck_mtproto_qa.go": "nodecheck_mtproto_qa.go.txt",
    "internal/dataplane/nodecheck_mtproto_qa_test.go": "nodecheck_mtproto_qa_test.go.txt",
    "cmd/nodeeval/nodeeval_qa.go": "nodeeval_qa.go.txt",
    "cmd/nodeeval/nodeeval_qa_test.go": "nodeeval_qa_test.go.txt",
    "cmd/nodeeval/nodeeval_qa_open_linux.go": "nodeeval_qa_open_linux.go.txt",
    "cmd/nodeeval/nodeeval_qa_open_other.go": "nodeeval_qa_open_other.go.txt",
    "cmd/nodeeval/nodeeval_qa_fifo_linux_test.go": "nodeeval_qa_fifo_linux_test.go.txt",
}


def replace_once(data, before, after):
    if data.count(before) != 1:
        raise ValueError("refusing a missing or ambiguous QA hook")
    return data.replace(before, after)


def prepare(source, output):
    source = Path(source).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("new QA output directory with existing parent required")
    output = output.parent.resolve(strict=True) / output.name
    if output == source or source.is_relative_to(output):
        raise ValueError("QA output cannot contain the source tree")
    if output.is_relative_to(source) and not output.is_relative_to(source / ".review-local"):
        raise ValueError("in-tree QA output must stay under .review-local")
    manifest = json.loads((PACKAGE / "source-pins.json").read_text(encoding="utf-8"))
    originals = {}
    for name, expected in manifest["source_sha256"].items():
        original = (source / name).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(original).hexdigest() != expected:
            raise ValueError("refusing a changed original source pin: " + name)
        originals[name] = original
    payloads = {}
    for name, payload in PAYLOADS.items():
        if (source / name).exists() or (source / name).is_symlink():
            raise ValueError("refusing an occupied virtual QA target")
        payloads[name] = (PACKAGE / "payload" / payload).read_bytes().replace(b"\r\n", b"\n")

    name = "internal/dataplane/nodecheck.go"
    checker = originals[name]
    checker = replace_once(checker, b"\tchecker.serviceProbe = checker.probeService\n",
                           b"\tchecker.serviceProbe = qaMTWrapService(checker, checker.probeService)\n")
    signature = b"func (c *ExactNodeChecker) Check(parent context.Context, request NodeCheckRequest) (result NodeCheckResult, resultErr error) {\n"
    checker = replace_once(checker, signature, signature +
                           b"\tvar qaMTAttempt *qaMTAttemptRecord\n"
                           b"\tdefer func() { qaMTFinalize(c, parent, request, qaMTAttempt, result, resultErr) }()\n")
    before = (b"\tif c.poisoned.Load() {\n\t\treturn NodeCheckResult{}, ErrExactNodeUnavailable\n\t}\n"
              b"\tctx, cancel := context.WithTimeout(parent, c.timeout())\n\tdefer cancel()\n")
    checker = replace_once(checker, before, before +
                           b"\tqaMTAttempt = qaMTNewAttempt(c, request)\n"
                           b"\tctx = context.WithValue(ctx, qaMTContextKey{}, qaMTAttempt)\n")
    before = ('\tresult.addStage("route_identity", "passed", "Процесс, конфигурация и локальный канал принадлежат этой проверке.", stageStarted, c.currentTime())\n').encode()
    checker = replace_once(checker, before, before + b"\tqaMTBind(qaMTAttempt, session, passport)\n")

    before = b"\treturn evaluate(workCtx, cleanupCtx, store, checker, checker.FreshProfile, o.limit, encoder)\n"
    after = (b"\t// Disposable QA overlay: original runtime, context and cleanup stay in use.\n"
             b"\tqa := newQACapture(w, encoder)\n"
             b"\tchecker.Processes = &qaProcessController{base: checker.Processes, capture: qa}\n"
             b"\tobservedChecker := &qaExactChecker{base: checker, capture: qa}\n"
             b"\tcode := evaluate(workCtx, cleanupCtx, store, observedChecker, checker.FreshProfile, o.limit, encoder)\n"
             b"\tqa.flush() // Publish diagnostics only after original Stop/Recover completed.\n"
             b"\treturn code\n")
    cli = replace_once(originals["cmd/nodeeval/main.go"], before, after)
    generated = {name: checker, "cmd/nodeeval/main.go": cli}

    # Validate every source, hook and payload before creating anything. O_EXCL
    # generation cannot overwrite an earlier QA run or its captured evidence.
    output.mkdir(mode=0o700)
    mapping = {}
    for index, (name, data) in enumerate({**generated, **payloads}.items()):
        target = output / (str(index) + "-" + Path(name).name)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o600)
        mapping[str(source / name)] = str(target)
    patch = "".join("".join(difflib.unified_diff(
        originals[name].decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile=name, tofile="QA/" + name)) for name, data in generated.items())
    for name, data in {
        "hooks.diff": patch,
        "overlay.json": json.dumps({"Replace": mapping}, indent=2) + "\n",
        "source-pins.json": json.dumps(manifest, indent=2) + "\n",
    }.items():
        with (output / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
        (output / name).chmod(0o600)
    return output / "overlay.json"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare_overlay.py SOURCE_ROOT NEW_OUTPUT_DIR")
    try:
        prepare(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, KeyError):
        # Input paths and errors can themselves contain private material.
        raise SystemExit("refused QA overlay: source pin, hook, payload or output boundary") from None
    print("prepared pinned MTProto/Stop QA overlay; source unchanged")
