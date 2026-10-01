//! Plain-text tables for the shared model.

use crate::model::*;
use std::fmt::Write;

#[derive(Clone, Debug, Default)]
pub struct Show {
    pub sections: bool,
    pub segments: bool,
    pub symbols: bool,
    pub imports: bool,
    pub exports: bool,
    pub relocations: bool,
    /// Rows per table; 0 means all.
    pub limit: usize,
    /// Keep only names containing this text (case-insensitive) in symbol, import and export tables.
    pub filter: Option<String>,
}

fn table(headers: &[&str], rows: &[Vec<String>], right: &[usize]) -> String {
    let mut w: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::from("  ");
        for (i, c) in cells.iter().enumerate() {
            let pad = w[i].saturating_sub(c.chars().count());
            if right.contains(&i) {
                s.push_str(&" ".repeat(pad));
                s.push_str(c);
            } else {
                s.push_str(c);
                if i + 1 < cells.len() {
                    s.push_str(&" ".repeat(pad));
                }
            }
            s.push_str("  ");
        }
        s.trim_end().to_string() + "\n"
    };
    let mut out = line(headers.to_vec());
    for r in rows {
        out += &line(r.iter().map(String::as_str).collect());
    }
    out
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

fn limited<'a, T>(items: &[&'a T], limit: usize) -> (Vec<&'a T>, usize) {
    let shown = if limit == 0 { items.len() } else { limit.min(items.len()) };
    (items[..shown].to_vec(), items.len() - shown)
}

fn matches(name: &str, filter: &Option<String>) -> bool {
    filter.as_ref().is_none_or(|f| name.to_lowercase().contains(&f.to_lowercase()))
}

pub fn render(bin: &Binary, file: &str, show: &Show) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "file:       {file}");
    let fmt = match bin.format {
        Format::Elf => "ELF",
        Format::Pe => "PE",
    };
    let _ = writeln!(o, "format:     {fmt}{}, {}-bit, {}, {} endian", if bin.format == Format::Pe && bin.bits == 64 { "32+" } else if bin.format == Format::Pe { "32" } else { "" }, bin.bits, bin.arch, bin.endian);
    let _ = writeln!(o, "type:       {}", bin.kind);
    let _ = write!(o, "entry:      {}", hex(bin.entry));
    if let Some(b) = bin.image_base {
        let _ = write!(o, "   image base: {}", hex(b));
    }
    o.push('\n');
    if let Some(i) = &bin.interpreter {
        let _ = writeln!(o, "interpreter: {i}");
    }
    if let Some(s) = &bin.soname {
        let _ = writeln!(o, "soname:     {s}");
    }
    if !bin.features.is_empty() {
        let _ = writeln!(o, "features:   {}", bin.features.join(", "));
    }
    if !bin.libraries.is_empty() {
        let shown = if show.limit == 0 { bin.libraries.len() } else { bin.libraries.len().min(6) };
        let more = bin.libraries.len() - shown;
        let _ = writeln!(
            o,
            "libraries:  {}{}",
            bin.libraries[..shown].join(", "),
            if more > 0 { format!(" ... and {more} more (--limit 0 for all)") } else { String::new() }
        );
    }
    let _ = writeln!(
        o,
        "counts:     {} sections, {} segments, {} symbols, {} imports, {} exports, {} relocations",
        bin.sections.len(),
        bin.segments.len(),
        bin.symbols.len(),
        bin.imports.len(),
        bin.exports.len(),
        bin.relocations.len()
    );
    for n in &bin.notes {
        let _ = writeln!(o, "note:       {n}");
    }

    let more = |o: &mut String, rest: usize| {
        if rest > 0 {
            let _ = writeln!(o, "  ... {rest} more (use --limit 0 for all)");
        }
    };

    if show.sections {
        let all: Vec<&Section> = bin.sections.iter().collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nsections:");
        let t: Vec<Vec<String>> = rows
            .iter()
            .enumerate()
            .map(|(i, s)| vec![i.to_string(), s.name.clone(), hex(s.address), hex(s.file_offset), hex(s.size), s.permissions.clone(), s.kind.clone()])
            .collect();
        o += &table(&["#", "name", "address", "offset", "size", "perm", "type"], &t, &[0, 2, 3, 4]);
        more(&mut o, rest);
    }
    if show.segments && !bin.segments.is_empty() {
        let all: Vec<&Segment> = bin.segments.iter().collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nsegments:");
        let t: Vec<Vec<String>> = rows
            .iter()
            .map(|s| vec![s.kind.clone(), hex(s.file_offset), hex(s.address), hex(s.file_size), hex(s.memory_size), s.permissions.clone()])
            .collect();
        o += &table(&["type", "offset", "address", "file size", "mem size", "perm"], &t, &[1, 2, 3, 4]);
        more(&mut o, rest);
    }
    if show.symbols {
        let all: Vec<&Symbol> = bin.symbols.iter().filter(|s| matches(&s.name, &show.filter)).collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nsymbols ({}):", all.len());
        let t: Vec<Vec<String>> = rows
            .iter()
            .map(|s| vec![hex(s.address), s.size.to_string(), s.kind.clone(), s.bind.clone(), s.section.clone(), s.table.to_string(), s.name.clone()])
            .collect();
        o += &table(&["address", "size", "type", "bind", "section", "table", "name"], &t, &[0, 1]);
        more(&mut o, rest);
    }
    if show.imports {
        let all: Vec<&Import> = bin.imports.iter().filter(|i| matches(&i.name, &show.filter) || matches(i.library.as_deref().unwrap_or(""), &show.filter) && show.filter.is_some()).collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nimports ({}):", all.len());
        let t: Vec<Vec<String>> = rows
            .iter()
            .map(|i| vec![i.library.clone().map_or("-".into(), |l| if i.delay_load { format!("{l} (delay)") } else { l }), if i.name.is_empty() { format!("#{}", i.ordinal.unwrap_or(0)) } else { i.name.clone() }])
            .collect();
        o += &table(&["library", "name"], &t, &[]);
        more(&mut o, rest);
    }
    if show.exports {
        let all: Vec<&Export> = bin.exports.iter().filter(|e| matches(e.name.as_deref().unwrap_or(""), &show.filter)).collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nexports ({}):", all.len());
        let t: Vec<Vec<String>> = rows
            .iter()
            .map(|e| vec![e.ordinal.map_or("-".into(), |x| x.to_string()), hex(e.address), e.name.clone().unwrap_or_else(|| "(by ordinal)".into()), e.forwarder.clone().unwrap_or_default()])
            .collect();
        o += &table(&["ordinal", "address", "name", "forwards to"], &t, &[0, 1]);
        more(&mut o, rest);
    }
    if show.relocations {
        let all: Vec<&Reloc> = bin.relocations.iter().collect();
        let (rows, rest) = limited(&all, show.limit);
        let _ = writeln!(o, "\nrelocations ({}):", all.len());
        let t: Vec<Vec<String>> = rows
            .iter()
            .map(|r| vec![hex(r.offset), r.kind.clone(), r.symbol.clone().unwrap_or_default(), r.addend.map_or(String::new(), |a| a.to_string())])
            .collect();
        o += &table(&["offset", "type", "symbol", "addend"], &t, &[0, 3]);
        more(&mut o, rest);
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let t = table(&["a", "bb"], &[vec!["1".into(), "x".into()], vec!["100".into(), "yyy".into()]], &[0]);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "    a  bb");
        assert_eq!(lines[1], "    1  x");
        assert_eq!(lines[2], "  100  yyy");
    }

    #[test]
    fn limit_reports_what_was_cut() {
        let v = [1, 2, 3, 4, 5];
        let refs: Vec<&i32> = v.iter().collect();
        assert_eq!(limited(&refs, 2).1, 3);
        assert_eq!(limited(&refs, 0).1, 0);
        assert_eq!(limited(&refs, 9).1, 0);
    }
}
