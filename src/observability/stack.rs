//! JS stack parsing and sourcemap symbolication.
//!
//! Handles the stack formats React Native produces:
//! - Hermes: `at fn (address at index.android.bundle:1:123456)` — the
//!   "column" is a bytecode offset; Expo's composed Hermes sourcemaps map
//!   (line 1, column = offset), so it's used as-is.
//! - V8-like: `at fn (file:line:col)` / `at file:line:col` (1-based column).
//! - JSC: `fn@file:line:col` / `@file:line:col` (1-based column).

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One stack frame, as reported and (if a sourcemap resolved it) original.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Frame {
    pub function: Option<String>,
    /// Reported location (bundle) …
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    /// … and the original source location when symbolicated.
    pub source: Option<String>,
    pub source_line: Option<u32>,
    pub source_column: Option<u32>,
    /// Not from node_modules / native code.
    pub in_app: bool,
    pub symbolicated: bool,
    #[serde(skip)]
    hermes_bytecode: bool,
}

/// Parse a stack string into frames (lines that aren't frames are skipped;
/// a leading "Error: message" line is ignored).
pub fn parse(stack: &str) -> Vec<Frame> {
    stack.lines().filter_map(parse_line).collect()
}

fn parse_line(raw: &str) -> Option<Frame> {
    let line = raw.trim();
    if line.is_empty() {
        return None;
    }
    let (function, loc) = if let Some(rest) = line.strip_prefix("at ") {
        match (rest.rfind(" ("), rest.ends_with(')')) {
            (Some(i), true) => (Some(&rest[..i]), &rest[i + 2..rest.len() - 1]),
            _ => (None, rest),
        }
    } else {
        // JSC `fn@file:line:col`; anything else ("Error: …" header, free
        // text) is not a frame.
        let i = line.find('@')?;
        (Some(&line[..i]), &line[i + 1..])
    };
    let function = function
        .map(str::trim)
        .filter(|f| !f.is_empty() && *f != "anonymous" && *f != "<anonymous>")
        .map(String::from);
    if loc == "native" || loc == "[native code]" {
        return Some(Frame {
            function,
            file: Some("[native code]".into()),
            line: None,
            column: None,
            source: None,
            source_line: None,
            source_column: None,
            in_app: false,
            symbolicated: false,
            hermes_bytecode: false,
        });
    }
    let (hermes_bytecode, loc) = match loc.strip_prefix("address at ") {
        Some(l) => (true, l),
        None => (false, loc),
    };
    // file:line:col, where file may itself contain ':' (URLs).
    let mut parts = loc.rsplitn(3, ':');
    let col = parts.next().and_then(|c| c.parse::<u32>().ok());
    let ln = parts.next().and_then(|l| l.parse::<u32>().ok());
    let (file, line_no, col) = match (ln, col, parts.next()) {
        (Some(l), Some(c), Some(f)) => (Some(f.to_string()), Some(l), Some(c)),
        _ => (Some(loc.to_string()), None, None),
    };
    let in_app = !file.as_deref().is_some_and(|f| f.contains("node_modules"));
    Some(Frame {
        function,
        file,
        line: line_no,
        column: col,
        source: None,
        source_line: None,
        source_column: None,
        in_app,
        symbolicated: false,
        hermes_bytecode,
    })
}

/// Map frames back to original sources with the bundle's sourcemap.
pub fn symbolicate(frames: &mut [Frame], map: &sourcemap::DecodedMap) {
    for f in frames.iter_mut() {
        let (Some(line), Some(col)) = (f.line, f.column) else {
            continue;
        };
        let (l0, c0) = if f.hermes_bytecode {
            (line.saturating_sub(1), col)
        } else {
            (line.saturating_sub(1), col.saturating_sub(1))
        };
        let Some(tok) = map.lookup_token(l0, c0) else {
            continue;
        };
        let Some(src) = tok.get_source() else {
            continue;
        };
        f.source = Some(src.to_string());
        f.source_line = Some(tok.get_src_line() + 1);
        f.source_column = Some(tok.get_src_col() + 1);
        if f.function.is_none() {
            f.function = tok.get_name().map(String::from);
        }
        f.in_app = !src.contains("node_modules");
        f.symbolicated = true;
    }
}

/// The frame that best explains the error: first in-app symbolicated frame,
/// else the first frame with a location.
pub fn culprit(frames: &[Frame]) -> Option<String> {
    let f = frames
        .iter()
        .find(|f| f.symbolicated && f.in_app)
        .or_else(|| frames.iter().find(|f| f.line.is_some()))?;
    let at = match (&f.source, f.source_line, &f.file, f.line) {
        (Some(s), Some(l), _, _) => format!("{s}:{l}"),
        (_, _, Some(file), Some(l)) => format!("{file}:{l}"),
        _ => return f.function.clone(),
    };
    Some(match &f.function {
        Some(func) => format!("{func} ({at})"),
        None => at,
    })
}

/// Grouping key: the error name plus its top three in-app symbolicated frames
/// (source + function, not line numbers, so it survives unrelated edits). With
/// nothing symbolicated, falls back to the name and the message with digits
/// masked (ids, counts) so near-identical errors still group.
pub fn fingerprint(name: &str, message: &str, frames: &[Frame]) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    let top: Vec<_> = frames
        .iter()
        .filter(|f| f.symbolicated && f.in_app)
        .take(3)
        .collect();
    if top.is_empty() {
        h.update(b"\0msg\0");
        let masked: String = message
            .chars()
            .map(|c| if c.is_ascii_digit() { '0' } else { c })
            .collect();
        h.update(masked.as_bytes());
    } else {
        for f in top {
            h.update(b"\0");
            h.update(f.source.as_deref().unwrap_or("").as_bytes());
            h.update(b"#");
            h.update(f.function.as_deref().unwrap_or("").as_bytes());
        }
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hermes_v8_and_jsc_frames() {
        let stack = "TypeError: undefined is not a function\n\
            at onPress (address at index.android.bundle:1:123456)\n\
            at anonymous (http://localhost:8081/index.bundle?platform=ios:12:34)\n\
            at callFn (native)\n\
            render@main.jsbundle:5:20\n\
            @main.jsbundle:6:1";
        let f = parse(stack);
        assert_eq!(f.len(), 5);
        assert_eq!(f[0].function.as_deref(), Some("onPress"));
        assert_eq!(f[0].file.as_deref(), Some("index.android.bundle"));
        assert_eq!((f[0].line, f[0].column), (Some(1), Some(123456)));
        assert!(f[0].hermes_bytecode);
        assert_eq!(
            f[1].file.as_deref(),
            Some("http://localhost:8081/index.bundle?platform=ios")
        );
        assert_eq!((f[1].line, f[1].column), (Some(12), Some(34)));
        assert_eq!(f[1].function, None);
        assert_eq!(f[2].file.as_deref(), Some("[native code]"));
        assert_eq!(f[3].function.as_deref(), Some("render"));
        assert_eq!(f[4].function, None);
    }

    #[test]
    fn symbolicates_with_a_sourcemap() {
        // Generated line 1 col 0..: "a" from src/App.tsx line 10 col 2 (name "boom").
        let map = br#"{"version":3,"sources":["src/App.tsx"],"names":["boom"],"mappings":"AASEA"}"#;
        let map = sourcemap::decode_slice(map).unwrap();
        let mut frames = parse("Error: x\n    at x (index.bundle:1:1)");
        symbolicate(&mut frames, &map);
        assert!(frames[0].symbolicated);
        assert_eq!(frames[0].source.as_deref(), Some("src/App.tsx"));
        assert_eq!(frames[0].source_line, Some(10));
        assert_eq!(culprit(&frames).as_deref(), Some("x (src/App.tsx:10)"));
    }

    #[test]
    fn fingerprint_ignores_digits_without_frames() {
        let a = fingerprint("Error", "user 123 not found", &[]);
        let b = fingerprint("Error", "user 456 not found", &[]);
        let c = fingerprint("Error", "timeout", &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
