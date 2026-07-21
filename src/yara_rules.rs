use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Rules, SourceCode};

// Bundled rules are embedded into the binary at compile time so `qilin` can
// detect known families/patterns standalone, without needing the source
// tree's `rules/` directory to be present at runtime.
const BUNDLED: &[(&str, &str)] = &[
    (
        "custom/upx_packed_pe.yar",
        include_str!("../rules/custom/upx_packed_pe.yar"),
    ),
    (
        "custom/powershell_encoded_command.yar",
        include_str!("../rules/custom/powershell_encoded_command.yar"),
    ),
    (
        "custom/linux_reverse_shell_oneliner.yar",
        include_str!("../rules/custom/linux_reverse_shell_oneliner.yar"),
    ),
    (
        "custom/mimikatz_strings.yar",
        include_str!("../rules/custom/mimikatz_strings.yar"),
    ),
    (
        "community/inquest/agenttesla.yar",
        include_str!("../rules/community/inquest/agenttesla.yar"),
    ),
    (
        "community/inquest/hex_encoded_powershell.yar",
        include_str!("../rules/community/inquest/hex_encoded_powershell.yar"),
    ),
    (
        "community/inquest/base64_encoded_powershell_directives.yar",
        include_str!("../rules/community/inquest/base64_encoded_powershell_directives.yar"),
    ),
    (
        "community/inquest/embedded_pe.yar",
        include_str!("../rules/community/inquest/embedded_pe.yar"),
    ),
    (
        "community/inquest/hidden_bee_elements.yar",
        include_str!("../rules/community/inquest/hidden_bee_elements.yar"),
    ),
];

pub struct RuleSet {
    pub rules: Rules,
    pub rule_count: usize,
}

/// Compile the bundled rules plus any user-supplied rule directories.
///
/// Each entry in `extra_dirs` gets its own YARA namespace (`external_0`,
/// `external_1`, ...) so a rule name in a user's directory can't collide
/// with a bundled rule of the same name.
pub fn compile(extra_dirs: &[PathBuf]) -> Result<RuleSet> {
    let mut compiler = Compiler::new();

    for (origin, src) in BUNDLED {
        compiler
            .add_source(SourceCode::from(*src).with_origin(*origin))
            .with_context(|| format!("bundled YARA rule {origin} failed to compile"))?;
    }

    for (i, dir) in extra_dirs.iter().enumerate() {
        compiler.new_namespace(&format!("external_{i}"));
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| is_yara_file(e.path()))
        {
            let path = entry.path();
            let src = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            compiler
                .add_source(SourceCode::from(src.as_str()).with_origin(path.to_string_lossy().as_ref()))
                .with_context(|| format!("{} failed to compile", path.display()))?;
        }
    }

    let rules = compiler.build();
    let rule_count = rules.iter().len();
    Ok(RuleSet { rules, rule_count })
}

fn is_yara_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("yar") | Some("yara")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_compile() {
        let set = compile(&[]).unwrap();
        assert_eq!(set.rule_count, BUNDLED.len());
    }

    #[test]
    fn detects_mimikatz_strings() {
        let set = compile(&[]).unwrap();
        let mut scanner = yara_x::Scanner::new(&set.rules);
        let data = b"mimikatz # sekurlsa::logonpasswords";
        let results = scanner.scan(data).unwrap();
        let matched: Vec<_> = results.matching_rules().map(|r| r.identifier().to_string()).collect();
        assert!(matched.contains(&"Qilin_Mimikatz_Artifacts".to_string()));
    }

    #[test]
    fn external_dir_gets_its_own_namespace() {
        let dir = std::env::temp_dir().join(format!("qilin-yara-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("custom.yar"),
            "rule External_Test_Rule { condition: true }",
        )
        .unwrap();

        let set = compile(&[dir.clone()]).unwrap();
        let mut scanner = yara_x::Scanner::new(&set.rules);
        let results = scanner.scan(b"anything").unwrap();
        let matched: Vec<_> = results
            .matching_rules()
            .map(|r| (r.namespace().to_string(), r.identifier().to_string()))
            .collect();
        assert!(matched.contains(&("external_0".to_string(), "External_Test_Rule".to_string())));

        std::fs::remove_dir_all(&dir).ok();
    }
}
