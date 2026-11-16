# Python SSRF model experiment

This standalone experiment trains a scikit-learn Bernoulli naive Bayes classifier to score potential server-side request forgery (SSRF) in Python. Python's AST provides features that describe how an outbound URL is built. The classifier learns from labeled examples.

From the repository root:

```powershell
cd experiments/ssrf_model
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe model.py train
.\.venv\Scripts\python.exe model.py evaluate
.\.venv\Scripts\python.exe model.py predict path/to/routes.py
```

Training writes `ssrf-model.pkl` to the current directory from the `train` split of `examples.json`. All three commands accept `--model PATH` for another artifact. Only load pickle files you created or trust. Retrain after changing scikit-learn versions. Prediction outputs candidate line numbers, uncalibrated model scores, feature names, and whether the score meets the experimental threshold of 0.5. An empty array means the extractor found no supported call.

The extractor recognizes direct calls to imported `requests`, `httpx`, and `urllib.request` functions in straight-line, top-level Python functions. It recognizes local FastAPI route declarations and typed request parameters, and follows simple local assignments. It does not resolve helpers, client instances, or branches. URL construction features do not yet distinguish a user-controlled hostname from a user-controlled path on a fixed host.

## Evaluation before scanner integration

The bundled synthetic examples keep each vulnerable/fixed pair in the same split. The held-out smoke evaluation currently finds 2 of 4 vulnerable examples, with 0 false alarms on 4 fixed examples. This dataset verifies the training and scoring workflow. Measure real-world performance separately using reviewed examples from multiple projects, with entire projects held out for testing. Include missed candidates when computing recall, and compare results with the current scanner on the same examples.

## Compare with PyTorch

In this directory, using the virtual environment above and Python 3.14:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-neural.txt
.\.venv\Scripts\python.exe neural.py compare
.\.venv\Scripts\python.exe neural.py predict path/to/routes.py
```

The comparison retrains both models on the same 96 labeled snippets from nine synthetic project groups. It evaluates both on 20 snippets from four separate synthetic groups and saves the PyTorch weights and vocabulary to `ssrf-neural.pt`. For each vulnerable/fixed pair, both examples stay in the same group. All examples in the comparison contain one outbound call. When the AST scanner can't extract a candidate, the baseline raises no flag and any vulnerable example still counts against recall.

The PyTorch model learns token and adjacent-token embeddings and produces a single score for a Python file. It uses a fixed seed and runs on CPU. Its score describes the file as a whole, so it cannot point to the affected line. The corpus uses hand-written patterns and repeated templates. Project separation here is synthetic, so the metrics measure behavior on these fixtures and cannot establish accuracy on real code. Neither model is wired into the scanners.

At the default threshold, scikit-learn caught 5 of 10 vulnerable snippets and PyTorch caught 6 of 10. Both raised zero false alarms on the 10 fixed snippets. PyTorch found the async client case that the AST extractor skipped, but missed the header alias and cookie lookup cases that scikit-learn caught. Both missed the helper case.
