# Check predecessor provenance against this allocation and the freshly fetched
# tag. Historical source is accepted only by the explicit manual workflow.
python3 - <<'PYTHON'
import json, os
from pathlib import Path
actual = json.loads(Path(os.environ["NGIT_CI_INPUTS"], "container/artifacts/provenance/provenance.json").read_text())
expected = {"tag": os.environ["NGIT_CI_REF"], "version": os.environ["version"],
            "source_commit": os.environ["release_revision"],
            "workflow_commit": os.environ["NGIT_CI_COMMIT_SHA"]}
if actual != expected:
    raise SystemExit("Container predecessor provenance differs from release context")
PYTHON
mkdir -p artifacts
cp -R "${NGIT_CI_INPUTS:?}/container/artifacts/layout" artifacts/ngit-grasp
ngit container publish ngit-grasp --repo "$repo" \
  --manifest .ngit/containers.yaml \
  --nbunksec-file "${NGIT_CI_SECRETS_DIR:?}/NGIT_PUBLISHER_NBUNKSEC" \
  --defaults --repo-relay-only --json
