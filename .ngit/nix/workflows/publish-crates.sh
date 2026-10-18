[[ $NGIT_CI_TRIGGER == push ]] || { echo 'Crate publication requires a tag push' >&2; exit 1; }
CARGO_REGISTRY_TOKEN=$(cat "${NGIT_CI_SECRETS_DIR:?}/CARGO_REGISTRY_TOKEN")
: "${CARGO_REGISTRY_TOKEN:?The CARGO_REGISTRY_TOKEN secret is empty}"
export CARGO_REGISTRY_TOKEN
cargo publish --locked --registry crates-io --package ngit-grasp
