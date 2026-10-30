// SPDX-License-Identifier: GPL-3.0-only

use crate::archive::RetentionPlan;
use crate::parser_type::ParserType;
use crate::parsers::parser_inputs;

/// Union of input globs for the selected parsers.
pub fn retention_plan(parsers: &[ParserType]) -> RetentionPlan {
    let mut selected = parsers.to_vec();
    selected.sort_by_key(|p| p.as_str());
    selected.dedup();
    let mut globs = Vec::new();
    let mut everything = false;
    for parser in &selected {
        let inputs = parser_inputs(*parser);
        if *parser == ParserType::plists {
            globs.push("**/*.plist".into());
        }
        if inputs.contains(&"**/*") {
            everything = true;
        }
        for glob in inputs {
            globs.push((*glob).to_string());
        }
    }
    globs.push("sysdiagnose.log".into());
    globs.sort();
    globs.dedup();
    RetentionPlan {
        globs,
        everything,
        paths_only: false,
    }
}
