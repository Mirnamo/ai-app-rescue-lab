"""Train and evaluate a standalone classifier for Python outbound calls."""

import argparse
import ast
import json
from pathlib import Path
import pickle

from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import confusion_matrix, precision_score, recall_score
from sklearn.naive_bayes import BernoulliNB
from sklearn.pipeline import make_pipeline


DATASET = Path(__file__).with_name("examples.json")
CLIENTS = {"requests", "httpx", "urllib.request"}
METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
INPUT_MEMBERS = {"query_params", "path_params", "form", "json", "headers", "cookies"}
FEATURE_VERSION = 1


def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def url_features(node, values, inputs):
    if isinstance(node, ast.Name):
        if node.id in values:
            return values[node.id] | {"assignment"}
        return {"request_input"} if node.id in inputs else {"unknown"}
    if isinstance(node, ast.Constant):
        return {"literal"}
    if isinstance(node, ast.Attribute):
        if name(node.value) in inputs and node.attr in INPUT_MEMBERS:
            return {"request_input", "request_member"}
        return {"unknown"}
    if isinstance(node, ast.Subscript):
        return url_features(node.value, values, inputs) | {"subscript"}
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
        features = {"constructed"}
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                features |= url_features(child, values, inputs)
        return features
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            return url_features(node.func.value, values, inputs) | {"lookup"}
        return {"function_result", "unknown"}
    return {"unknown"}


def candidates(source):
    tree = ast.parse(source)
    aliases = {}
    fastapi_objects = set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        if isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for item in statement.names:
                aliases[item.asname or item.name] = f"{statement.module}.{item.name}"

    def qualified(node):
        first, dot, rest = name(node).partition(".")
        return aliases.get(first, first) + dot + rest

    for statement in tree.body:
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call):
            if qualified(statement.value.func) in {"fastapi.FastAPI", "fastapi.APIRouter"}:
                fastapi_objects.update(target.id for target in statement.targets if isinstance(target, ast.Name))

    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_route = any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and name(decorator.func.value) in fastapi_objects
            and decorator.func.attr in {"get", "post", "put", "patch", "delete", "head", "api_route"}
            for decorator in function.decorator_list
        )
        inputs = {
            arg.arg
            for arg in function.args.posonlyargs + function.args.args + function.args.kwonlyargs
            if is_route or qualified(arg.annotation) in {"fastapi.Request", "starlette.requests.Request"}
        }
        values = {}
        for statement in function.body:
            if isinstance(statement, ast.Return):
                expression = statement.value
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr)):
                expression = statement.value
            else:
                # Later values can depend on control flow this prototype cannot resolve.
                break
            call = expression.value if isinstance(expression, ast.Await) else expression
            if isinstance(call, ast.Call):
                client, _, method = qualified(call.func).rpartition(".")
                if client in CLIENTS and method in METHODS:
                    keyword = next((kw.value for kw in call.keywords if kw.arg in {"url", "fullurl"}), None)
                    position = 1 if method == "request" else 0
                    url = keyword if keyword is not None else (
                        call.args[position] if len(call.args) > position else None
                    )
                    if url is not None:
                        yield call.lineno, sorted(url_features(url, values, inputs))
            if isinstance(statement, (ast.Assign, ast.AnnAssign)) and expression is not None:
                features = url_features(expression, values, inputs)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = features
            if isinstance(statement, ast.Return):
                break


def load_examples(split):
    examples = []
    for case in json.loads(DATASET.read_text(encoding="utf-8"))[split]:
        for label in ("vulnerable", "fixed"):
            matches = list(candidates(case["prefix"] + "\n" + case[label]))
            if len(matches) != 1:
                raise ValueError(f"{case['id']} ({label}) must produce exactly one candidate")
            _, features = matches[0]
            examples.append((f"{case['id']}/{label}", features, int(label == "vulnerable")))
    return examples


def train(examples):
    model = make_pipeline(DictVectorizer(), BernoulliNB(alpha=1.0, binarize=None))
    return model.fit(
        [dict.fromkeys(features, 1) for _, features, _ in examples],
        [label for _, _, label in examples],
    )


def scores(model, feature_rows):
    rows = [dict.fromkeys(features, 1) for features in feature_rows]
    if not rows:
        return []
    return model.predict_proba(rows)[:, 1].tolist()


def evaluate(model):
    examples = load_examples("test")
    values = scores(model, (features for _, features, _ in examples))
    expected = [label for _, _, label in examples]
    predictions = [int(value >= 0.5) for value in values]
    for (case, _, label), prediction, value in zip(examples, predictions, values, strict=True):
        print(f"{case:35} expected={label} flagged={prediction} score={value:.3f}")
    tn, fp, fn, tp = confusion_matrix(expected, predictions, labels=[0, 1]).ravel()
    precision = precision_score(expected, predictions, zero_division=float("nan"))
    recall = recall_score(expected, predictions, zero_division=float("nan"))
    print(f"TP={tp} FP={fp} TN={tn} FN={fn} precision={precision:.2f} recall={recall:.2f}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("train", "evaluate", "predict"):
        subcommand = commands.add_parser(command)
        subcommand.add_argument("--model", type=Path, default=Path("ssrf-model.pkl"))
        if command == "predict":
            subcommand.add_argument("source", type=Path)
    args = parser.parse_args()
    if args.command == "train":
        model = train(load_examples("train"))
        args.model.write_bytes(pickle.dumps({"feature_version": FEATURE_VERSION, "pipeline": model}))
        print(f"Saved {args.model}")
        return
    try:
        artifact = pickle.loads(args.model.read_bytes())
    except (OSError, pickle.UnpicklingError, EOFError) as error:
        parser.error(f"Could not read model. Run train first. {error}")
    if artifact["feature_version"] != FEATURE_VERSION:
        parser.error("This model uses a different feature version. Train a new model.")
    model = artifact["pipeline"]
    if args.command == "evaluate":
        evaluate(model)
        return
    try:
        matches = list(candidates(args.source.read_text(encoding="utf-8-sig")))
    except (OSError, SyntaxError, UnicodeError) as error:
        parser.error(str(error))
    output = []
    values = scores(model, (features for _, features in matches))
    for (line, features), value in zip(matches, values, strict=True):
        output.append({"line": line, "score": round(value, 6), "flagged": value >= 0.5, "features": features})
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
