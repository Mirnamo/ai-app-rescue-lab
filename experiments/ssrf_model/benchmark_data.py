"""Paired SSRF examples grouped by synthetic Python applications."""

from dataclasses import dataclass
import textwrap


@dataclass(frozen=True)
class Example:
    project: str
    case: str
    source: str
    label: int


def pair(project, case, template, vulnerable, fixed):
    for label, expression in ((1, vulnerable), (0, fixed)):
        yield Example(project, case, textwrap.dedent(template).replace("<URL>", expression), label)


def route_pairs(project, imports, declaration, outbound, cases):
    for case, setup, vulnerable, fixed in cases:
        template = (
            f"{imports}\n{declaration}\n"
            + textwrap.indent(setup + f"return {outbound}\n", "    ")
        )
        yield from pair(project, case, template, vulnerable, fixed)


FASTAPI = "from fastapi import FastAPI, Request\napp = FastAPI()"
ORIGIN = '"https://media.example.test"'


def training_examples():
    # Variants within each synthetic project share a framework and call style.
    for project, imports, declaration, outbound in (
        ("preview", FASTAPI + "\nimport requests", '@app.get("/preview")\ndef view(request: Request):',
         "requests.get(<URL>, allow_redirects=False)"),
        ("mirror", FASTAPI + "\nimport httpx", '@app.get("/mirror")\ndef mirror(request: Request):',
         "httpx.get(url=<URL>, follow_redirects=False)"),
        ("relay", FASTAPI + "\nfrom requests import request as send",
         '@app.post("/relay")\ndef relay(request: Request):', 'send("POST", <URL>, allow_redirects=False)'),
        ("asset", FASTAPI + "\nfrom urllib.request import urlopen",
         '@app.get("/asset")\ndef asset(request: Request):', "urlopen(<URL>)"),
        ("catalog", FASTAPI + "\nimport requests as http",
         '@app.get("/catalog")\ndef catalog(request: Request):', "http.head(<URL>, allow_redirects=False)"),
        ("metadata", FASTAPI + "\nfrom httpx import request as send",
         '@app.get("/info")\ndef metadata(request: Request):', 'send("GET", <URL>, follow_redirects=False)'),
    ):
        yield from route_pairs(project, imports, declaration, outbound, (
            ("query", "", 'request.query_params["url"]', ORIGIN),
            ("assignment", 'target = request.query_params.get("target")\n', "target", ORIGIN),
            ("headers", "", 'request.headers["x-target"]', ORIGIN),
            ("cookies", 'target = request.cookies["target"]\n', "target", ORIGIN),
            ("constructed", 'host = request.query_params["host"]\n', 'f"https://{host}/items"', ORIGIN),
            ("indirect", 'target = request.query_params["target"]\nselected = target\n', "selected", ORIGIN),
        ))

    for project, imports, declaration, outbound in (
        ("thumbnail", FASTAPI + "\nimport requests", '@app.get("/thumb")\ndef thumb(segment: str):',
         "requests.get(<URL>, allow_redirects=False)"),
        ("billing", FASTAPI + "\nimport httpx", '@app.get("/bill")\ndef bill(segment: str):',
         "httpx.get(<URL>, follow_redirects=False)"),
        ("link-map", FASTAPI + "\nfrom requests import get",
         '@app.get("/link")\ndef link(segment: str):', "get(<URL>, allow_redirects=False)"),
    ):
        yield from route_pairs(project, imports, declaration, outbound, (
            ("host-vs-path", "", 'f"https://{segment}/icons"', 'f"https://example.test/icons/{segment}"'),
            ("concat", "", '"https://" + segment + "/details"', '"https://example.test/details/" + segment'),
            ("local-helper", "", "identity(segment)", "identity('https://example.test')"),
            ("route-argument", "", "segment", ORIGIN),
        )) if False else ()
        yield from route_pairs(project, imports + "\ndef identity(value):\n    return value", declaration, outbound, (
            ("host-vs-path", "", 'f"https://{segment}/icons"', 'f"https://example.test/icons/{segment}"'),
            ("concat", "", '"https://" + segment + "/details"', '"https://example.test/details/" + segment'),
            ("local-helper", "", "identity(segment)", "identity('https://example.test')"),
            ("route-argument", "", "segment", ORIGIN),
        ))


def test_examples():
    yield from route_pairs(
        "webhook-checker", FASTAPI + "\nimport requests as transport",
        '@app.post("/validate")\ndef validate(req: Request):', "transport.head(<URL>, allow_redirects=False)",
        (
            ("header-alias", 'raw = req.headers.get("callback")\naddress = raw\n', "address", ORIGIN),
            ("cookie-lookup", "", 'req.cookies.get("destination")', ORIGIN),
            ("path-params", "", 'req.path_params["endpoint"]', ORIGIN),
        ),
    )
    yield from route_pairs(
        "document-renderer",
        FASTAPI + "\nfrom httpx import get as download\ndef resolve(value):\n    return value",
        '@app.get("/render")\ndef generate(value: str):', "download(url=<URL>, follow_redirects=False)",
        (
            ("helper", "", "resolve(value)", "resolve('https://docs.example.test')"),
            ("fixed-authority", "", 'f"https://{value}/pages/"', 'f"https://docs.example.test/pages/{value}"'),
            ("different-formats", "", '"https://{}/read".format(value)', '"https://docs.example.test/read/{}".format(value)'),
        ),
    )
    yield from route_pairs(
        "flask-feed", "from flask import Flask, request\nimport requests\napp = Flask(__name__)",
        '@app.get("/feed")\ndef feed():', "requests.get(<URL>, allow_redirects=False)",
        (
            ("flask-args", "", 'request.args["remote"]', ORIGIN),
            ("flask-headers", 'address = request.headers.get("x-remote")\n', "address", ORIGIN),
            ("flask-formatted", 'host = request.args.get("host")\n', 'f"https://{host}/feed"', 'f"https://news.example.test/feed/{host}"'),
        ),
    )
    yield from pair(
        "async-status", "client-instance",
        """
        from fastapi import FastAPI
        import httpx
        app = FastAPI()
        @app.get("/status")
        async def status(destination: str):
            async with httpx.AsyncClient() as client:
                return await client.get(<URL>)
        """,
        "destination", ORIGIN,
    )
