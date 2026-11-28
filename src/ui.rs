// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Shared terminal presentation; evidence files never contain terminal styling.
use console::{Color, Style, Term};
use indicatif::{HumanCount, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    fmt::Display,
    io::{self, IsTerminal},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use unicode_width::UnicodeWidthStr;

pub const LOGO: &str = include_str!("../art/logo.txt");
const GREEN: Color = Color::TrueColor(0, 255, 0);
const RED: Color = Color::TrueColor(255, 0, 0);
const WHITE: Color = Color::TrueColor(255, 255, 255);
static PRINTED_HUMAN_OUTPUT: AtomicBool = AtomicBool::new(false);

fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && console::colors_enabled()
}

fn paint(text: &str, color: Color, enabled: bool) -> String {
    Style::new()
        .for_stdout()
        .fg(color)
        .force_styling(enabled)
        .apply_to(text)
        .to_string()
}

fn safe_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn field_line(label: &str, value: &str, color: Color, enabled: bool) -> String {
    format!(
        "{} {}",
        paint(&format!("{}:", safe_text(label)), GREEN, enabled),
        paint(&safe_text(value), color, enabled)
    )
}

fn print_line(line: String) {
    println!("{line}");
    PRINTED_HUMAN_OUTPUT.store(true, Ordering::Relaxed);
}

/// Separate the final human-readable line from the next shell prompt.
pub fn finish() {
    if PRINTED_HUMAN_OUTPUT.load(Ordering::Relaxed) && io::stdout().is_terminal() {
        println!();
    }
}

pub fn field(label: &str, value: impl Display) {
    print_line(field_line(
        label,
        &value.to_string(),
        WHITE,
        colors_enabled(),
    ));
}

pub(crate) fn error_field(label: &str, value: &str) {
    print_line(field_line(label, value, RED, colors_enabled()));
}

pub fn heading(text: &str) {
    print_line(paint(&safe_text(text), GREEN, colors_enabled()));
}

pub fn status(text: &str) {
    print_line(paint(&safe_text(text), WHITE, colors_enabled()));
}

pub fn banner() {
    println!("\n{}", paint(LOGO.trim_end(), GREEN, colors_enabled()));
    println!();
    field("Version", env!("CARGO_PKG_VERSION"));
    println!();
}

pub fn count(value: u64) -> HumanCount {
    HumanCount(value)
}

fn progress_template(enabled: bool, length: u64, columns: usize) -> String {
    let total = HumanCount(length);
    let overhead = format!("[00:00:00] {total} / {total} ⠋ [] 100%").width();
    let (prefix, bar) = if columns >= overhead + 40 {
        ("[{elapsed_precise}] {human_pos} / {human_len} ", "{bar:40}")
    } else if columns > overhead {
        (
            "[{elapsed_precise}] {human_pos} / {human_len} ",
            "{wide_bar}",
        )
    } else if columns >= 21 {
        ("[{elapsed_precise}] ", "{wide_bar}")
    } else if columns >= 10 {
        ("", "{wide_bar}")
    } else {
        return format!(
            "{}\n\n{}",
            paint("{spinner}", GREEN, enabled),
            paint("{wide_msg}", WHITE, enabled)
        );
    };
    format!(
        "{}{} {}{}{}",
        paint(prefix, WHITE, enabled),
        paint("{spinner}", GREEN, enabled),
        paint("[", WHITE, enabled),
        paint(bar, GREEN, enabled),
        paint("] {percent}%\n\n{wide_msg}", WHITE, enabled)
    )
}

pub fn progress_bar(length: u64, quiet: bool) -> ProgressBar {
    if quiet {
        return ProgressBar::hidden();
    }
    let columns = Term::stdout().size().1 as usize;
    let bar = ProgressBar::with_draw_target(Some(length), ProgressDrawTarget::stdout_with_hz(10))
        .with_tab_width(55);
    bar.set_style(
        ProgressStyle::with_template(&progress_template(colors_enabled(), length, columns))
            .expect("static progress template is valid")
            .progress_chars("=> "),
    );
    bar.enable_steady_tick(Duration::from_millis(300));
    bar
}

/// Drive discovery has no known total until enumeration finishes.
pub fn scan_spinner(quiet: bool) -> ProgressBar {
    if quiet {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stdout_with_hz(10));
    bar.set_style(
        ProgressStyle::with_template(&format!(
            "{} {} {}\n\n{}",
            paint("[{elapsed_precise}]", WHITE, colors_enabled()),
            paint("{spinner}", GREEN, colors_enabled()),
            paint("{human_pos} files inspected", WHITE, colors_enabled()),
            paint("{wide_msg}", WHITE, colors_enabled())
        ))
        .expect("static scan template is valid"),
    );
    bar.enable_steady_tick(Duration::from_millis(300));
    bar
}

pub fn progress_message(path: &str, size: Option<u64>) -> String {
    let width = Term::stdout().size().1 as usize;
    message_with_width(path, size, width)
}

fn message_with_width(path: &str, size: Option<u64>, width: usize) -> String {
    let size = size
        .map(crate::collect::human_bytes)
        .unwrap_or_else(|| "size unknown".into());
    let suffix = format!("\" ({size})");
    let available = width.saturating_sub(1 + suffix.width());
    if available == 0 {
        return crate::collect::clip_label(&format!("\"{path}{suffix}"), width);
    }
    format!(
        "\"{}{suffix}",
        crate::collect::clip_label(&path.replace('\\', "/"), available)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_green_and_values_are_white_without_color_bleed() {
        let line = field_line("Unknown sizes", "28", WHITE, true);
        assert_eq!(
            line,
            "\x1b[38;2;0;255;0mUnknown sizes:\x1b[0m \x1b[38;2;255;255;255m28\x1b[0m"
        );
        assert_eq!(
            field_line("Unknown sizes", "28", WHITE, false),
            "Unknown sizes: 28"
        );
    }

    #[test]
    fn untrusted_field_values_cannot_inject_terminal_commands() {
        let line = field_line("Results saved", "test\x1b[2J\npath", RED, false);
        assert!(!line.contains('\x1b'));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn progress_templates_match_the_shared_layout_and_handle_small_terminals() {
        let normal = progress_template(false, 37_279, 80);
        assert_eq!(
            normal,
            "[{elapsed_precise}] {human_pos} / {human_len} {spinner} [{bar:40}] {percent}%\n\n{wide_msg}"
        );
        let colored = progress_template(true, 37_279, 80);
        assert!(colored.contains("\x1b[38;2;0;255;0m{spinner}\x1b[0m"));
        assert!(colored.contains("\x1b[38;2;0;255;0m{bar:40}\x1b[0m"));
        for width in [0, 5, 15, 30, 50, 80, 120] {
            for enabled in [false, true] {
                assert!(
                    ProgressStyle::with_template(&progress_template(enabled, 1_000_000, width))
                        .is_ok()
                );
            }
        }
        assert!(!progress_template(false, 1_000_000, 30).contains("{human_len}"));
        assert!(progress_template(false, 1_000_000, 50).contains("{wide_bar}"));
    }

    #[test]
    fn filenames_fit_the_terminal_and_preserve_sizes_when_space_allows() {
        let path = format!("C/{}\x1b[2J\nfile.pf", "証拠/".repeat(100));
        for width in [0, 1, 5, 12, 20, 40, 80] {
            let message = message_with_width(&path, Some(2048), width);
            assert!(message.width() <= width, "{width}: {message:?}");
            assert!(!message.contains('\x1b'));
            assert!(!message.contains('\n'));
            if width >= 20 {
                assert!(message.ends_with("(2.0 KiB)"));
            }
        }
    }
}
