"""tools/openapi_loader.py(P4.1)の固定試験。通信ゼロをソケット遮断で確認する。"""
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

from tools import openapi_loader as ol


def doc(paths, **extra):
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": paths, **extra}


def q(name, **kw):
    return {"name": name, "in": "query", **kw}


class LoaderBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, d, name="api.json", raw=None):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(raw if raw is not None else json.dumps(d))
        return p


class NoNetworkTest(LoaderBase):
    def test_external_servers_and_refs_cause_zero_connections(self):
        d = doc({"/a": {"get": {"parameters": [q("x", schema={"type": "string"})]}},
                 "/ext": {"$ref": "http://evil.example/p.json#/x"}},
                servers=[{"url": "http://evil.example/v1"}])
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network used")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
             mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns used")):
            loaded = ol.load_openapi(self.write(d))
            with self.assertRaises(ol.OpenApiError):          # 外部$refは明示エラー(取得しない)
                ol.list_operations(loaded)
            d["paths"].pop("/ext")
            ops = ol.list_operations(ol.load_openapi(self.write(d)))
            pts = ol.select_points(ops, ["GET /a"], "http://127.0.0.1:9/")
        self.assertEqual({p["url"] for p in pts}, {"http://127.0.0.1:9/a"})      # serversは使われない


class OperationTest(LoaderBase):
    def ops(self, d):
        return {o.operation_id: o for o in ol.list_operations(ol.load_openapi(self.write(d)))}

    def test_selectability_rules(self):
        ops = self.ops(doc({
            "/items": {"get": {"operationId": "listItems", "parameters": [q("page", schema={"type": "integer"})]},
                       "post": {"operationId": "createItem", "parameters": [q("x")]}},
            "/items/{id}": {"get": {"operationId": "getItem", "parameters": [q("v"),
                                                                              {"name": "id", "in": "path", "required": True}]}},
            "/search": {"get": {"parameters": [q("q", required=True, schema={"enum": ["a", "b"]})],
                                "requestBody": {"content": {}}}},
            "/noparams": {"get": {}},
            "/ok": {"parameters": [q("shared", schema={"type": "boolean"})], "get": {"parameters": [q("own", schema={"default": 7})]}},
        }))
        self.assertTrue(ops["listItems"].selectable)
        self.assertEqual(ops["listItems"].query_params[0].sample, "1")
        self.assertIn("GET以外", ops["createItem"].reason)
        self.assertIn("path parameter", ops["getItem"].reason)
        self.assertIn("body", ops["GET /search"].reason)
        self.assertIn("query parameterが無い", ops["GET /noparams"].reason)
        ok = ops["GET /ok"]
        self.assertEqual([(p.name, p.sample) for p in ok.query_params], [("shared", "true"), ("own", "7")])

    def test_operation_level_parameter_overrides_path_level(self):
        ops = self.ops(doc({"/p": {"parameters": [q("a", schema={"default": "shared"})],
                                   "get": {"parameters": [q("a", schema={"default": "own"})]}}}))
        self.assertEqual([p.sample for p in ops["GET /p"].query_params], ["own"])

    def test_local_refs_resolve_and_cycles_are_rejected(self):
        d = doc({"/r": {"get": {"parameters": [{"$ref": "#/components/parameters/P"}]}}},
                components={"parameters": {"P": q("id", schema={"$ref": "#/components/schemas/S"})},
                            "schemas": {"S": {"type": "integer", "default": 5}}})
        self.assertEqual(self.ops(d)["GET /r"].query_params[0].sample, "5")
        cyc = doc({"/r": {"get": {"parameters": [{"$ref": "#/components/parameters/A"}]}}},
                  components={"parameters": {"A": {"$ref": "#/components/parameters/B"},
                                             "B": {"$ref": "#/components/parameters/A"}}})
        with self.assertRaises(ol.OpenApiError) as cm:
            self.ops(cyc)
        self.assertIn("循環", str(cm.exception))
        deep = {"parameters": {f"P{i}": {"$ref": f"#/components/parameters/P{i + 1}"} for i in range(40)}}
        deep["parameters"]["P40"] = q("x")
        with self.assertRaises(ol.OpenApiError) as cm:
            self.ops(doc({"/r": {"get": {"parameters": [{"$ref": "#/components/parameters/P0"}]}}}, components=deep))
        self.assertIn("深さ", str(cm.exception))
        with self.assertRaises(ol.OpenApiError):
            self.ops(doc({"/r": {"get": {"parameters": [{"$ref": "#/components/parameters/Missing"}]}}}, components={"parameters": {}}))

    def test_limits_and_invalid_documents(self):
        many = {f"/p{i}": {"get": {"parameters": [q("a")]}} for i in range(ol.MAX_OPERATIONS + 1)}
        with self.assertRaises(ol.OpenApiError):
            self.ops(doc(many))
        with self.assertRaises(ol.OpenApiError):
            self.ops(doc({"/x": {"get": {"parameters": [q(f"p{i}") for i in range(ol.MAX_PARAMS_PER_OPERATION + 1)]}}}))
        with self.assertRaises(ol.OpenApiError):
            self.ops(doc({"/x": {"get": {"operationId": "d"}, "post": {"operationId": "d"}}}))      # id重複
        for raw in ("not json", json.dumps({"swagger": "2.0", "paths": {}}),
                    json.dumps({"openapi": "3.0.0"}), json.dumps(["x"])):
            with self.assertRaises(ol.OpenApiError, msg=raw):
                ol.load_openapi(self.write(None, raw=raw))
        with self.assertRaises(ol.OpenApiError):
            ol.load_openapi(os.path.join(self.tmp.name, "missing.json"))
        big = self.write(None, raw=json.dumps(doc({})) + " " * (ol.MAX_BYTES + 1))
        with self.assertRaises(ol.OpenApiError):
            ol.load_openapi(big)


class YamlTest(LoaderBase):
    """YAML対応(仕様変更): 旧版は「openapi: 3.0.0\\npaths: {}」を非対応として拒否していたが、今は有効なYAMLとして読む。"""
    YAML = ("openapi: 3.0.3\ninfo: {title: t, version: '1'}\nservers:\n  - url: http://evil.example/v1\n"
            "paths:\n  /a:\n    get:\n      operationId: a\n      parameters:\n"
            "        - {name: x, in: query, schema: {type: integer}, example: 2020-01-01}\n")

    def test_yaml_is_read_and_behaves_like_json_without_network(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network used")), \
             mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns used")):
            loaded = ol.load_openapi(self.write(None, "api.yaml", raw=self.YAML))
            ops = ol.list_operations(loaded)
        self.assertEqual([o.operation_id for o in ops], ["a"])
        self.assertEqual(ol.load_openapi(self.write(None, "m.yaml", raw="openapi: 3.0.0\npaths: {}"))["paths"], {})

    def test_yaml_aliases_python_tags_and_garbage_are_rejected(self):
        bomb = "openapi: 3.0.0\nx: &a [1,2,3]\ny: [*a, *a, *a]\npaths: {}\n"
        for raw in (bomb, "openapi: 3.0.0\npaths: !!python/object/apply:os.system ['id']\n",
                    "openapi: [unclosed\n", "\t- bad: : :"):
            with self.assertRaises(ol.OpenApiError, msg=raw):
                ol.load_openapi(self.write(None, "bad.yaml", raw=raw))

    def test_deeply_nested_yaml_is_an_error_not_a_crash(self):
        with self.assertRaises(ol.OpenApiError):
            ol.load_openapi(self.write(None, "deep.yaml", raw="openapi: 3.0.0\npaths: {}\nz: " + "[" * 5000 + "]" * 5000))


class SelectionTest(LoaderBase):
    def setUp(self):
        super().setUp()
        d = doc({"/a": {"get": {"operationId": "a", "parameters": [q("x"), q("y", schema={"type": "integer"})]}},
                 "/b": {"get": {"operationId": "b", "parameters": [q("z")]}},
                 "/c/{id}": {"get": {"operationId": "c", "parameters": [q("w")]}},
                 "/d": {"post": {"operationId": "d", "parameters": [q("w")]}}})
        self.ops = ol.list_operations(ol.load_openapi(self.write(d)))

    def test_selection_is_explicit_and_exclusion_wins(self):
        with self.assertRaises(ol.OpenApiError):
            ol.select_points(self.ops, [], "http://127.0.0.1/")             # 全自動選択はしない
        pts = ol.select_points(self.ops, ["a", "b"], "http://127.0.0.1:8080", exclude=["b"])
        self.assertEqual([(p["url"], p["param"], p["method"]) for p in pts],
                         [("http://127.0.0.1:8080/a", "x", "GET"), ("http://127.0.0.1:8080/a", "y", "GET")])
        self.assertEqual(pts[0]["fields"], {"x": "test", "y": "1"})
        self.assertEqual(pts[0]["source"], "openapi:a")

    def test_unknown_or_unselectable_operations_are_errors_not_silent(self):
        for sel in (["nope"], ["c"], ["d"]):
            with self.assertRaises(ol.OpenApiError, msg=sel):
                ol.select_points(self.ops, sel, "http://127.0.0.1/")
        with self.assertRaises(ol.OpenApiError):
            ol.select_points(self.ops, ["a"], "http://127.0.0.1/", exclude=["nope"])
        with self.assertRaises(ol.OpenApiError):
            ol.select_points(self.ops, ["a"], "ftp://x/")


class FuzzerSeedTest(unittest.TestCase):
    def test_seed_points_merge_dedupe_and_reject_other_origins(self):
        from testlab.fixtures.web_benchmark import BenchmarkServer
        from tools.web_fuzzer import WebFuzzer
        with BenchmarkServer() as srv:
            base = srv.base_url.rstrip("/")
            f = WebFuzzer(profile="aggressive", max_pages=5, max_requests=100, target=srv.base_url,
                          tls_verify=False, tls_ca_bundle="")
            f.seed_points = [
                {"url": base + "/unlinked", "method": "GET", "where": "query", "param": "k", "fields": {"k": "1"}, "source": "openapi:x"},
                {"url": base + "/search", "method": "GET", "where": "query", "param": "q", "fields": {"q": "dup"}},   # クロールと重複
                {"url": "http://192.0.2.1/evil", "method": "GET", "where": "query", "param": "k", "fields": {"k": "1"}},
            ]
            pts = f.crawl(srv.base_url)["injection_points"]
            keys = [(p["url"], p["param"]) for p in pts]
            self.assertIn((base + "/unlinked", "k"), keys)
            self.assertEqual(keys.count((base + "/search", "q")), 1)                  # 重複はクロール側を優先して1件
            self.assertNotIn(("http://192.0.2.1/evil", "k"), keys)
            self.assertEqual(len(f.seed_rejected), 1)
            self.assertIn("同一origin外", f.seed_rejected[0])


if __name__ == "__main__":
    unittest.main()
