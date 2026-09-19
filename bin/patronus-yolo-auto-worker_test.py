import importlib.util
import stat
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("patronus-yolo-auto-worker.py")
spec = importlib.util.spec_from_file_location("patronus_worker", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class PatronusWorkerMappingTests(unittest.TestCase):
    def test_l1_safe_requires_complete_native_result(self):
        result = module.map_l1_result({
            "category": "injection",
            "class_name": "safe",
            "confidence": 1.0,
            "level": "L1",
            "model": "native:injection_l1",
            "decision": {
                "terminality": {"completion": "complete", "degraded": False},
                "provenance": {"model": "native:injection_l1"},
            },
        })
        self.assertEqual(result["verdict"], "safe")
        self.assertTrue(result["accepted"])
        self.assertTrue(result["complete"])
        self.assertFalse(result["degraded"])

    def test_l2_maps_tag_result_order_to_pipeline_names(self):
        raw = [
            {"category": "injection", "class_name": "benign", "level": "L2", "confidence": 0.99},
            {"category": "tool_class", "class_name": "file", "level": "L2", "confidence": 0.99},
            {"category": "tool_action", "class_name": "read", "level": "L2", "confidence": 0.99},
            {"category": "tool_tags", "class_name": "absent", "level": "L2", "confidence": 0.99},
            {"category": "tool_tags", "class_name": "absent", "level": "L2", "confidence": 0.99},
            {"category": "tool_tags", "class_name": "absent", "level": "L2", "confidence": 0.99},
        ]
        results = module.map_l2_results(raw)
        self.assertEqual([item.get("pipeline") for item in results if item["category"] == "tool_tags"], [
            "source_sensitive", "source_untrusted", "sink_external",
        ])
        self.assertEqual(results[0]["className"], "safe")

    def test_payload_text_excludes_absolute_paths(self):
        text = module.payload_text({
            "toolName": "read",
            "operation": "read",
            "workspaceRelativePath": "src/index.ts",
        })
        self.assertNotIn("/Users/", text)
        self.assertIn("src/index.ts", text)


class _FakeGateway:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.warmups = 0
        _FakeGateway.instances.append(self)

    def warmup(self):
        self.warmups += 1

    def stop_l3_models(self):
        pass


class PatronusWorkerStartupTests(unittest.TestCase):
    def test_startup_cache_lock_is_private_and_reusable(self):
        with tempfile.TemporaryDirectory() as directory:
            model_dir = Path(directory) / "models"
            with module.startup_cache_lock(model_dir):
                lock_path = model_dir / ".pi-sentinel-yolo-auto.lock"
                self.assertTrue(lock_path.is_file())
                self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)
            with module.startup_cache_lock(model_dir):
                self.assertTrue(lock_path.is_file())

    def test_failed_competing_worker_does_not_remove_active_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "worker.sock"
            socket_path.touch()
            module.cleanup_worker_socket(socket_path, owns_socket=False)
            self.assertTrue(socket_path.exists())

    def test_rejects_unpinned_l2_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "injection" / "l2_ntdb" / "injection_current"
            package.mkdir(parents=True)
            (package / ".patronus-revision").write_text("wrong\n")
            (package / "manifest.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "revision mismatch"):
                module.verify_cached_l2_assets(Path(directory))

    def test_rejects_tampered_l2_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "injection" / "l2_ntdb" / "injection_current"
            package.mkdir(parents=True)
            (package / ".patronus-revision").write_text(
                "142fadc5474163d4c483cb761d5a6b02e3aa1741\n",
            )
            (package / "manifest.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                module.verify_cached_l2_assets(Path(directory))

    def test_resolves_relative_model_dir_before_ark_access(self):
        class FakeArk:
            SecurityGateway = _FakeGateway

        previous = sys.modules.get("patronus_ark")
        sys.modules["patronus_ark"] = FakeArk
        _FakeGateway.instances.clear()
        try:
            provider = module.PatronusProvider("relative-models", None, download_files=False)
            provider.warm_l2()
            provider.warm_l3()
            self.assertTrue(all(Path(item.kwargs["model_dir"]).is_absolute() for item in _FakeGateway.instances))
        finally:
            if previous is None:
                sys.modules.pop("patronus_ark", None)
            else:
                sys.modules["patronus_ark"] = previous

    def test_warm_all_downloads_assets_before_serving(self):
        class FakeArk:
            SecurityGateway = _FakeGateway

        previous = sys.modules.get("patronus_ark")
        sys.modules["patronus_ark"] = FakeArk
        _FakeGateway.instances.clear()
        previous_verify = module.verify_cached_l2_assets
        module.verify_cached_l2_assets = lambda _: None
        try:
            provider = module.PatronusProvider("/tmp/models", None, download_files=True)
            provider.warm_all()
            self.assertEqual(len(_FakeGateway.instances), 2)
            self.assertTrue(all(item.kwargs["download_files"] for item in _FakeGateway.instances))
            self.assertEqual([item.warmups for item in _FakeGateway.instances], [1, 1])
        finally:
            module.verify_cached_l2_assets = previous_verify
            if previous is None:
                sys.modules.pop("patronus_ark", None)
            else:
                sys.modules["patronus_ark"] = previous




if __name__ == "__main__":
    unittest.main()
