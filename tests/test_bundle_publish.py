from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from pipeline.common import sha256
from pipeline.harbor import (
    merge_shared_images,
    publish_bundle,
    scan_docker_archive,
    validate_bundle_archives,
)


def _write_manifest(path: Path, archive: Path, image: str) -> None:
    path.write_text(json.dumps({
        "schema_version": 1,
        "archive": {
            "file": archive.name,
            "image": image,
            "image_id": "sha256:" + "1" * 64,
            "sha256": sha256(archive),
        },
    }), encoding="utf-8")


def _layer_tar(names: list[str]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as layer:
        for name in names:
            info = tarfile.TarInfo(name)
            payload = b"x"
            info.size = len(payload)
            layer.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def _docker_archive(path: Path, names: list[str]) -> None:
    with tarfile.open(path, "w:gz") as outer:
        payload = _layer_tar(names)
        info = tarfile.TarInfo("layer.tar")
        info.size = len(payload)
        outer.addfile(info, io.BytesIO(payload))


class SharedImageMergeTests(unittest.TestCase):
    def test_missing_agent_archive_is_merged_into_existing_shared_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "staging/shared-images"
            destination = root / "root/shared-images"
            source.mkdir(parents=True)
            destination.mkdir(parents=True)
            (destination / "verifier.tar.gz").write_bytes(b"verifier")
            (source / "agent.tar.gz").write_bytes(b"agent")
            _write_manifest(source / "agent.tar.manifest.json", source / "agent.tar.gz", "agent:1")
            merge_shared_images(source, destination)
            self.assertEqual((destination / "agent.tar.gz").read_bytes(), b"agent")
            self.assertTrue((destination / "agent.tar.manifest.json").is_file())

    def test_same_name_with_different_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "staging/shared-images"
            destination = root / "root/shared-images"
            source.mkdir(parents=True)
            destination.mkdir(parents=True)
            (source / "verifier.tar.gz").write_bytes(b"new-verifier")
            (destination / "verifier.tar.gz").write_bytes(b"old-verifier")
            with self.assertRaisesRegex(ValueError, "differs from already published"):
                merge_shared_images(source, destination)


class BundleValidationTests(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        task = root / "task"
        images = task / "images"
        images.mkdir(parents=True)
        shared = root / "shared-images"
        shared.mkdir()
        (images / "target.tar.gz").write_bytes(b"target")
        (shared / "verifier.tar.gz").write_bytes(b"verifier")
        (task / "image-lock.json").write_text(json.dumps({
            "schema_version": 1,
            "task": "task",
            "images": [
                {"role": "target", "ref": "target:1", "archive": "images/target.tar.gz",
                 "sha256": sha256(images / "target.tar.gz")},
                {"role": "verifier", "ref": "verifier:1",
                 "archive": "../shared-images/verifier.tar.gz",
                 "sha256": sha256(shared / "verifier.tar.gz")},
            ],
        }), encoding="utf-8")
        (images / "manifest.json").write_text(json.dumps({
            "archives": [{"file": "target.tar.gz", "image": "target:1",
                          "sha256": sha256(images / "target.tar.gz")}],
        }), encoding="utf-8")
        profile = task / "harbor-runtime-profile"
        (profile / "environment").mkdir(parents=True)
        (profile / "instruction.md").write_text("test\n", encoding="utf-8")
        (profile / "task.toml").write_text(
            '[verifier.environment]\nnetwork_mode = "public"\n'
            '[environment]\nnetwork_mode = "public"\n', encoding="utf-8")
        (profile / "environment/docker-compose.yaml").write_text(
            "services:\n"
            "  main:\n    image: agent:1\n    healthcheck:\n      test: ['CMD', 'true']\n"
            "  client:\n    image: target:1\n    healthcheck:\n      test: ['CMD', 'true']\n",
            encoding="utf-8")
        return task

    def test_valid_bundle_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validate_bundle_archives(self._bundle(root), root)

    def test_missing_shared_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = self._bundle(root)
            (root / "shared-images/verifier.tar.gz").unlink()
            with self.assertRaisesRegex(FileNotFoundError, "image archive is missing"):
                validate_bundle_archives(task, root)

    def test_dockerfile_and_timeout_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = self._bundle(root)
            (task / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Dockerfile"):
                validate_bundle_archives(task, root)
            (task / "Dockerfile").unlink()
            (task / "harbor-runtime-profile/task.toml").write_text(
                '[environment]\ntimeout_sec = 10\nnetwork_mode = "public"\n',
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "timeout_sec"):
                validate_bundle_archives(task, root)


class PublishBundleTests(unittest.TestCase):
    def test_publish_merges_shared_agent_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            staging = Path(directory) / "staging"
            task = staging / "task"
            images = task / "images"
            images.mkdir(parents=True)
            (images / "target.tar.gz").write_bytes(b"target")
            (images / "manifest.json").write_text(json.dumps({
                "archives": [{"file": "target.tar.gz", "image": "target:1",
                              "sha256": sha256(images / "target.tar.gz")}],
            }), encoding="utf-8")
            shared = staging / "shared-images"
            shared.mkdir()
            (shared / "agent.tar.gz").write_bytes(b"agent")
            _write_manifest(shared / "agent.tar.manifest.json", shared / "agent.tar.gz", "agent:1")
            root_shared = root / "shared-images"
            root_shared.mkdir(parents=True)
            (root_shared / "verifier.tar.gz").write_bytes(b"verifier")
            (task / "image-lock.json").write_text(json.dumps({
                "schema_version": 1,
                "task": "task",
                "images": [
                    {"role": "agent", "ref": "agent:1",
                     "archive": "../shared-images/agent.tar.gz",
                     "sha256": sha256(shared / "agent.tar.gz")},
                    {"role": "target", "ref": "target:1",
                     "archive": "images/target.tar.gz",
                     "sha256": sha256(images / "target.tar.gz")},
                    {"role": "verifier", "ref": "verifier:1",
                     "archive": "../shared-images/verifier.tar.gz",
                     "sha256": sha256(root_shared / "verifier.tar.gz")},
                ],
            }), encoding="utf-8")
            profile = task / "harbor-runtime-profile"
            (profile / "environment").mkdir(parents=True)
            (profile / "instruction.md").write_text("test\n", encoding="utf-8")
            (profile / "task.toml").write_text(
                '[verifier.environment]\nnetwork_mode = "public"\n'
                '[environment]\nnetwork_mode = "public"\n', encoding="utf-8")
            (profile / "environment/docker-compose.yaml").write_text(
                "services:\n"
                "  main:\n    image: agent:1\n    healthcheck:\n      test: ['CMD', 'true']\n"
                "  client:\n    image: target:1\n    healthcheck:\n      test: ['CMD', 'true']\n",
                encoding="utf-8")
            acceptance = Path(directory) / "acceptance.json"
            acceptance.write_text('{"status": "passed"}\n', encoding="utf-8")
            publish_bundle(staging, root, "task", acceptance)
            self.assertEqual((root / "shared-images/agent.tar.gz").read_bytes(), b"agent")
            self.assertTrue((root / "task/image-lock.json").is_file())
            self.assertTrue((root / "task/acceptance.json").is_file())


class ImageArchiveScanTests(unittest.TestCase):
    def test_private_path_in_layer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "target.tar.gz"
            _docker_archive(archive, ["opt/private/gold-input.bin"])
            with self.assertRaisesRegex(ValueError, "private delivery material"):
                scan_docker_archive(archive)

    def test_clean_layer_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "target.tar.gz"
            _docker_archive(archive, ["usr/bin/app", "etc/passwd"])
            scan_docker_archive(archive)


if __name__ == "__main__":
    unittest.main()