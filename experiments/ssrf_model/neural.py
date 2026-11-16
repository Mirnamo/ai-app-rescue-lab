"""Train and compare a small CPU PyTorch classifier for Python SSRF."""

import argparse
from collections import Counter
import io
import json
from pathlib import Path
import tokenize

from sklearn.metrics import confusion_matrix, precision_score, recall_score
import torch
from torch import nn

from benchmark_data import test_examples, training_examples
from model import candidates, scores as baseline_scores, train as train_baseline


SEED = 42
EPOCHS = 50
THRESHOLD = 0.5
CHECKPOINT_VERSION = 1


def code_tokens(source):
    tokens = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in {tokenize.NAME, tokenize.OP}:
            tokens.append(token.string)
        elif token.type in {tokenize.STRING, tokenize.NUMBER, tokenize.FSTRING_MIDDLE}:
            # Preserve URL shape without learning literal hostnames.
            if token.string.strip("'\"") in {"https://", "http://"}:
                tokens.append("<scheme>")
            else:
                tokens.append(tokenize.tok_name[token.type])
        elif token.type in {tokenize.NEWLINE, tokenize.FSTRING_START, tokenize.FSTRING_END}:
            tokens.append(tokenize.tok_name[token.type])
    return tokens + [f"{left} {right}" for left, right in zip(tokens, tokens[1:])]


def batch(token_rows, vocabulary):
    indices = []
    offsets = []
    for row in token_rows:
        offsets.append(len(indices))
        indices.extend(vocabulary.get(token, 0) for token in row)
    return torch.tensor(indices, dtype=torch.long), torch.tensor(offsets, dtype=torch.long)


class TokenClassifier(nn.Module):
    def __init__(self, vocabulary_size):
        super().__init__()
        self.embedding = nn.EmbeddingBag(vocabulary_size, 24, mode="mean", padding_idx=0)
        self.classifier = nn.Sequential(nn.Linear(24, 16), nn.ReLU(), nn.Linear(16, 1))

    def forward(self, indices, offsets):
        return self.classifier(self.embedding(indices, offsets)).squeeze(-1)


def train_neural(examples):
    torch.manual_seed(SEED)
    token_rows = [code_tokens(example.source) for example in examples]
    counts = Counter(token for row in token_rows for token in row)
    vocabulary = {token: index for index, token in enumerate(
        sorted(token for token, count in counts.items() if count >= 2), start=1
    )}
    inputs = batch(token_rows, vocabulary)
    expected = torch.tensor([example.label for example in examples], dtype=torch.float32)
    model = TokenClassifier(len(vocabulary) + 1)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.02)
    loss_function = nn.BCEWithLogitsLoss()
    for _ in range(EPOCHS):
        optimizer.zero_grad()
        loss = loss_function(model(*inputs), expected)
        loss.backward()
        optimizer.step()
    return model.eval(), vocabulary


@torch.inference_mode()
def predict(model, vocabulary, sources):
    inputs = batch([code_tokens(source) for source in sources], vocabulary)
    return model(*inputs).sigmoid().tolist()


def baseline_rows(examples):
    for example in examples:
        features = [features for _, features in candidates(example.source)]
        if len(features) > 1:
            raise ValueError(f"Expected at most one outbound call in {example.project}/{example.case}")
        yield features[0] if features else None


def report(name, expected, values):
    flags = [int(value is not None and value >= THRESHOLD) for value in values]
    tn, fp, fn, tp = confusion_matrix(expected, flags, labels=[0, 1]).ravel()
    precision = precision_score(expected, flags, zero_division=0)
    recall = recall_score(expected, flags, zero_division=0)
    missed_candidates = values.count(None)
    print(
        f"{name:13} TP={tp} FP={fp} TN={tn} FN={fn} "
        f"precision={precision:.2f} recall={recall:.2f} no_candidate={missed_candidates}"
    )


def compare(checkpoint):
    training = list(training_examples())
    testing = list(test_examples())
    train_projects = {example.project for example in training}
    test_projects = {example.project for example in testing}
    if train_projects & test_projects:
        raise ValueError("Training and test projects overlap")
    if {example.source for example in training} & {example.source for example in testing}:
        raise ValueError("Training and test source overlap")

    baseline = train_baseline([
        (example.case, features, example.label)
        for example, features in zip(training, baseline_rows(training), strict=True)
        if features is not None
    ])
    model, vocabulary = train_neural(training)
    torch.save({
        "version": CHECKPOINT_VERSION,
        "vocabulary": vocabulary,
        "weights": model.state_dict(),
    }, checkpoint)

    expected = [example.label for example in testing]
    feature_rows = list(baseline_rows(testing))
    scored = iter(baseline_scores(baseline, (row for row in feature_rows if row is not None)))
    baseline_values = [next(scored) if row is not None else None for row in feature_rows]
    neural_values = predict(model, vocabulary, [example.source for example in testing])
    print(f"Training: {len(training)} snippets from {len(train_projects)} synthetic projects")
    print(f"Test: {len(testing)} snippets from {len(test_projects)} held-out synthetic projects")
    for example, baseline_value, neural_value in zip(testing, baseline_values, neural_values, strict=True):
        base = "n/a" if baseline_value is None else f"{baseline_value:.3f}"
        print(f"{example.project}/{example.case} label={example.label} sklearn={base} torch={neural_value:.3f}")
    report("scikit-learn", expected, baseline_values)
    report("PyTorch", expected, neural_values)
    print(f"Saved {checkpoint}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=Path("ssrf-neural.pt"))
    parser.add_argument("command", choices=("compare", "predict"))
    parser.add_argument("source", type=Path, nargs="?")
    args = parser.parse_args()
    torch.set_num_threads(1)
    if args.command == "compare":
        if args.source is not None:
            parser.error("compare uses the benchmark corpus")
        compare(args.checkpoint)
        return
    if args.source is None:
        parser.error("predict requires a Python source file")
    if not args.checkpoint.is_file():
        parser.error("checkpoint not found; run compare first")
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=True)
    if checkpoint["version"] != CHECKPOINT_VERSION:
        parser.error("unsupported checkpoint version; run compare again")
    vocabulary = checkpoint["vocabulary"]
    model = TokenClassifier(len(vocabulary) + 1)
    model.load_state_dict(checkpoint["weights"])
    source = args.source.read_text(encoding="utf-8-sig")
    value, = predict(model.eval(), vocabulary, [source])
    print(json.dumps({"score": round(value, 6), "flagged": value >= THRESHOLD}))


if __name__ == "__main__":
    main()
