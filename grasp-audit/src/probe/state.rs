//! Complete branch and tag comparison for audit probes.

use std::collections::{BTreeMap, HashMap};

/// Compare only branches and unpeeled tags. HEAD, protocol capabilities,
/// peeled annotated tags and refs/nostr are not repository-state refs.
pub(super) fn ref_mismatches(
    expected: &HashMap<String, String>,
    actual: &[(String, String)],
) -> Vec<String> {
    let actual: BTreeMap<_, _> = actual
        .iter()
        .filter(|(name, _)| {
            (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
                && !name.ends_with("^{}")
        })
        .map(|(name, hash)| (name.as_str(), hash.as_str()))
        .collect();
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|(name, hash)| (name.as_str(), hash.as_str()))
        .collect();
    let mut mismatches = Vec::new();
    for (name, hash) in &expected {
        match actual.get(name) {
            Some(actual) if actual == hash => {}
            Some(actual) => mismatches.push(format!("{name}: expected {hash} got {actual}")),
            None => mismatches.push(format!("{name}: expected {hash} not found in refs")),
        }
    }
    for name in actual.keys() {
        if !expected.contains_key(name) {
            mismatches.push(format!("{name}: unexpected ref"));
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_comparison_requires_complete_branch_and_tag_set() {
        let expected: HashMap<String, String> = HashMap::from([
            ("refs/heads/main".into(), "abc".into()),
            ("refs/tags/v1".into(), "def".into()),
        ]);
        let mut actual: Vec<_> = expected
            .iter()
            .map(|(name, hash)| (name.clone(), hash.clone()))
            .collect();
        actual.extend([
            ("HEAD".into(), "abc".into()),
            ("refs/nostr/test".into(), "abc".into()),
            ("refs/tags/v1^{}".into(), "abc".into()),
        ]);
        assert!(ref_mismatches(&expected, &actual).is_empty());
        actual.push(("refs/heads/stale".into(), "abc".into()));
        actual.push(("refs/tags/stale".into(), "def".into()));
        assert_eq!(
            ref_mismatches(&expected, &actual),
            [
                "refs/heads/stale: unexpected ref",
                "refs/tags/stale: unexpected ref",
            ]
        );
        assert_eq!(ref_mismatches(&HashMap::new(), &actual).len(), 4);
        assert!(ref_mismatches(&HashMap::new(), &[]).is_empty());
        assert_eq!(ref_mismatches(&expected, &[]).len(), 2);
        actual[0].1 = "wrong".into();
        assert!(ref_mismatches(&expected, &actual)
            .iter()
            .any(|error| error.contains("got wrong")));
    }
}
