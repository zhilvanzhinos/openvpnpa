Sources are pinned for a reproducible compatibility investigation:

* `service.proto`: verbatim from `PasarGuard/node` commit
  `739eab94a9343d9f0035baf7162796844109f4c4`, `common/service.proto`.
* `panel_usage.py`: the two named function excerpts from `PasarGuard/panel`
  commit `2b75db15cb0019a00252c59f9d1c34e6082a121f`,
  `app/jobs/record_usages.py`. Imports were reduced to their dependencies.
  The only function-body adaptation is `except ValueError, TypeError:` →
  `except (ValueError, TypeError):` for Ubuntu 24.04's Python 3.12.
* `source_hashes.json`: SHA-256 of the COMPLETE original files, before extraction.
* `../openvpnpa/service_pb2.py`: generated from the vendored schema using
  `grpcio-tools==1.76.0` (protobuf 6.33.0). Generation command:

  ```sh
  python -m grpc_tools.protoc -I vendor --python_out=openvpnpa vendor/service.proto
  ```

Upstream license texts are preserved verbatim in `licenses/NODE_LICENSE` (GPL)
and `licenses/PANEL_LICENSE` (AGPL). The combined lab uses the panel's AGPL
license text in `../LICENSE`. This is a separate experimental project and is
not endorsed by PasarGuard. No upstream application is installed or patched.
