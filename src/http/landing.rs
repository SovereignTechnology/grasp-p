/// Landing Page Handler
///
/// Generates HTML landing page for the Nostr relay.
use crate::config::Config;
use crate::git::percent_encode;
use crate::http::nip11::RelayInformationDocument;
use std::collections::HashMap;

/// Get the software version string (version + optional git commit)
fn get_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match option_env!("GIT_COMMIT_SHORT") {
        Some(commit) if !commit.is_empty() => format!("v{}-{}", version, commit),
        _ => format!("v{}", version),
    }
}

/// Generate the footer JavaScript that sets the domain dynamically
fn get_footer_script() -> &'static str {
    r#"<script>
        (function() {
            var footerDomain = document.getElementById('footer-domain');
            if (footerDomain) {
                footerDomain.textContent = window.location.host;
            }
        })();
    </script>"#
}

/// Generate the theme toggle HTML button
fn get_theme_toggle_html() -> &'static str {
    r##"<button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme" title="Toggle light/dark mode">
        <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 000-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>
        </svg>
        <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <path d="M12 3a9 9 0 109 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 01-4.4 2.26 5.403 5.403 0 01-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>
        </svg>
    </button>"##
}

/// Generate the theme toggle JavaScript
fn get_theme_script() -> &'static str {
    r#"<script>
        (function() {
            const THEME_KEY = 'grasp-theme';
            const toggle = document.getElementById('theme-toggle');
            
            // Get saved theme or null (use system preference)
            function getSavedTheme() {
                try {
                    return localStorage.getItem(THEME_KEY);
                } catch (e) {
                    return null;
                }
            }
            
            // Save theme preference
            function saveTheme(theme) {
                try {
                    if (theme) {
                        localStorage.setItem(THEME_KEY, theme);
                    } else {
                        localStorage.removeItem(THEME_KEY);
                    }
                } catch (e) {}
            }
            
            // Get current effective theme
            function getCurrentTheme() {
                const saved = getSavedTheme();
                if (saved) return saved;
                return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
            }
            
            // Apply theme to document
            function applyTheme(theme) {
                if (theme) {
                    document.documentElement.setAttribute('data-theme', theme);
                } else {
                    document.documentElement.removeAttribute('data-theme');
                }
            }
            
            // Initialize theme on page load
            const savedTheme = getSavedTheme();
            if (savedTheme) {
                applyTheme(savedTheme);
            }
            
            // Toggle theme on button click
            if (toggle) {
                toggle.addEventListener('click', function() {
                    const current = getCurrentTheme();
                    const newTheme = current === 'dark' ? 'light' : 'dark';
                    applyTheme(newTheme);
                    saveTheme(newTheme);
                });
            }
            
            // Listen for system theme changes
            window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
                // Only react if no manual preference is set
                if (!getSavedTheme()) {
                    // Theme will auto-update via CSS, no JS needed
                }
            });
        })();
    </script>"#
}

/// Generate the common base CSS used across all pages
fn get_base_css() -> &'static str {
    r#"/* Dark mode (default) */
        :root {
            --brand: #4434FF;
            --brand-light: #6b5fff;
            --bg: #0a0a0f;
            --surface: #12121a;
            --border: #1e1e2e;
            --text: #e4e4eb;
            --text-muted: #a8a8bd;
            --error: #ff4444;
            --success: #22c55e;
            --logo-bg: #4434FF;
            --logo-icon: white;
        }
        /* Light mode - system preference */
        @media (prefers-color-scheme: light) {
            :root:not([data-theme="dark"]) {
                --brand: #4434FF;
                --brand-light: #3525cc;
                --bg: #f8f9fa;
                --surface: #ffffff;
                --border: #e1e4e8;
                --text: #1a1a2e;
                --text-muted: #586069;
                --error: #dc3545;
                --success: #28a745;
                --logo-bg: #4434FF;
                --logo-icon: white;
            }
        }
        /* Manual light mode override */
        :root[data-theme="light"] {
            --brand: #4434FF;
            --brand-light: #3525cc;
            --bg: #f8f9fa;
            --surface: #ffffff;
            --border: #e1e4e8;
            --text: #1a1a2e;
            --text-muted: #586069;
            --error: #dc3545;
            --success: #28a745;
            --logo-bg: #4434FF;
            --logo-icon: white;
        }
        /* Manual dark mode override */
        :root[data-theme="dark"] {
            --brand: #4434FF;
            --brand-light: #6b5fff;
            --bg: #0a0a0f;
            --surface: #12121a;
            --border: #1e1e2e;
            --text: #e4e4eb;
            --text-muted: #a8a8bd;
            --error: #ff4444;
            --success: #22c55e;
            --logo-bg: #4434FF;
            --logo-icon: white;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
            line-height: 1.6;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        a { color: var(--brand-light); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
            background: var(--border);
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 0.875rem;
            color: var(--brand-light);
        }
        /* Theme toggle button */
        .theme-toggle {
            position: fixed;
            top: 16px;
            right: 16px;
            z-index: 1000;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 50%;
            width: 44px;
            height: 44px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .theme-toggle:hover {
            transform: scale(1.1);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        .theme-toggle svg {
            width: 20px;
            height: 20px;
            fill: var(--text);
            transition: fill 0.3s ease;
        }
        .theme-toggle .sun-icon { display: none; }
        .theme-toggle .moon-icon { display: block; }
        :root[data-theme="light"] .theme-toggle .sun-icon,
        :root:not([data-theme="dark"]) .theme-toggle .sun-icon { display: block; }
        :root[data-theme="light"] .theme-toggle .moon-icon,
        :root:not([data-theme="dark"]) .theme-toggle .moon-icon { display: none; }
        @media (prefers-color-scheme: dark) {
            :root:not([data-theme="light"]) .theme-toggle .sun-icon { display: none; }
            :root:not([data-theme="light"]) .theme-toggle .moon-icon { display: block; }
        }
        .footer {
            margin-top: 48px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
        }
        .footer-separator {
            margin: 0 0.5em;
            opacity: 0.5;
        }
        .software-box {
            display: flex;
            align-items: flex-start;
            gap: 16px;
            text-align: left;
        }
        .software-logo {
            width: 48px;
            height: 48px;
            flex-shrink: 0;
        }
        .software-logo rect {
            fill: var(--logo-bg);
        }
        .software-logo path {
            fill: var(--logo-icon);
        }
        .software-content {
            flex: 1;
        }
        .software-heading {
            font-size: 1.125rem;
            font-weight: 500;
            margin-bottom: 8px;
            color: var(--text-muted);
        }
        .software-heading a {
            color: var(--brand-light);
        }
        .software-heading a:hover {
            text-decoration: underline;
        }
        .software-desc {
            color: var(--text-muted);
            font-size: 0.9rem;
            line-height: 1.5;
        }"#
}

/// Metadata for a NIP (title and description for the landing page)
struct NipMetadata {
    title: &'static str,
    description: &'static str,
}

/// Metadata for a GRASP (title and description for the landing page)
struct GraspMetadata {
    title: &'static str,
    description: &'static str,
}

/// Get known NIP metadata for landing page display
fn get_nip_metadata() -> HashMap<u16, NipMetadata> {
    let mut map = HashMap::new();
    map.insert(
        1,
        NipMetadata {
            title: "Basic Protocol",
            description: "Core Nostr protocol flow and event structure",
        },
    );
    map.insert(
        11,
        NipMetadata {
            title: "Relay Information",
            description: "Relay metadata and capabilities document",
        },
    );
    map.insert(
        34,
        NipMetadata {
            title: "Git Events",
            description: "Repository announcements and state tracking",
        },
    );
    map.insert(
        77,
        NipMetadata {
            title: "Negentropy Sync",
            description: "Efficient set reconciliation protocol",
        },
    );
    map
}

/// Get known GRASP metadata for landing page display
fn get_grasp_metadata() -> HashMap<&'static str, GraspMetadata> {
    let mut map = HashMap::new();
    map.insert(
        "GRASP-01",
        GraspMetadata {
            title: "Nostr Authorised HTTP Git Server",
            description: "with embedded Nostr Relay",
        },
    );
    map
}

/// Generate hero section tags HTML from NIP-11 document
fn generate_hero_tags(nip11: &RelayInformationDocument) -> String {
    let mut html = String::new();

    // Add GRASP tags
    for grasp in &nip11.supported_grasps {
        html.push_str(&format!(r#"<span class="tag tag-grasp">{}</span>"#, grasp));
        html.push('\n');
    }

    // Add NIP tags
    for nip in &nip11.supported_nips {
        html.push_str(&format!(
            r#"<span class="tag tag-nip">NIP-{:02}</span>"#,
            nip
        ));
        html.push('\n');
    }

    html
}

/// Generate detailed GRASP cards HTML from NIP-11 document
fn generate_grasp_cards(nip11: &RelayInformationDocument) -> String {
    let metadata = get_grasp_metadata();
    let mut html = String::new();

    for grasp in &nip11.supported_grasps {
        if let Some(meta) = metadata.get(grasp.as_str()) {
            html.push_str(&format!(
                r#"<div class="card">
                <div class="card-title"><span class="badge">{}</span>{}</div>
                <div class="card-desc">{}</div>
            </div>"#,
                grasp, meta.title, meta.description
            ));
        } else {
            // Fallback for unknown GRASPs - still show them
            html.push_str(&format!(
                r#"<div class="card">
                <div class="card-title"><span class="badge">{}</span>{}</div>
            </div>"#,
                grasp, grasp
            ));
        }
        html.push('\n');
    }

    html
}

/// Generate detailed NIP cards HTML from NIP-11 document
fn generate_nip_cards(nip11: &RelayInformationDocument) -> String {
    let metadata = get_nip_metadata();
    let mut html = String::new();

    for nip in &nip11.supported_nips {
        if let Some(meta) = metadata.get(nip) {
            html.push_str(&format!(
                r#"<div class="card">
                <div class="card-title"><span class="badge badge-nip">NIP-{:02}</span> {}</div>
                <div class="card-desc">{}</div>
            </div>"#,
                nip, meta.title, meta.description
            ));
        } else {
            // Fallback for unknown NIPs - still show them
            html.push_str(&format!(
                r#"<div class="card">
                <div class="card-title"><span class="badge badge-nip">NIP-{:02}</span></div>
            </div>"#,
                nip
            ));
        }
        html.push('\n');
    }

    html
}

/// Escape HTML special characters
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Generate table rows for NIP-11 relay information
fn generate_relay_info_rows(nip11: &RelayInformationDocument) -> String {
    let mut html = String::new();

    // Follow NIP-11 document order:
    // name
    html.push_str(&format!(
        r#"<tr><th>name</th><td>{}</td></tr>"#,
        escape_html(&nip11.name)
    ));
    html.push('\n');

    // description
    html.push_str(&format!(
        r#"<tr><th>description</th><td>{}</td></tr>"#,
        escape_html(&nip11.description)
    ));
    html.push('\n');

    // pubkey (if present)
    if let Some(ref pubkey) = nip11.pubkey {
        html.push_str(&format!(
            r#"<tr><th>pubkey</th><td><code>{}</code></td></tr>"#,
            escape_html(pubkey)
        ));
        html.push('\n');
    }

    // contact (if present)
    if let Some(ref contact) = nip11.contact {
        html.push_str(&format!(
            r#"<tr><th>contact</th><td>{}</td></tr>"#,
            escape_html(contact)
        ));
        html.push('\n');
    }

    // supported_nips
    let nips_str = nip11
        .supported_nips
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    html.push_str(&format!(
        r#"<tr><th>supported_nips</th><td>{}</td></tr>"#,
        nips_str
    ));
    html.push('\n');

    // software
    html.push_str(&format!(
        r#"<tr><th>software</th><td><a href="{}">{}</a></td></tr>"#,
        escape_html(&nip11.software),
        escape_html(&nip11.software)
    ));
    html.push('\n');

    // version
    html.push_str(&format!(
        r#"<tr><th>version</th><td>{}</td></tr>"#,
        escape_html(&nip11.version)
    ));
    html.push('\n');

    // icon (if present)
    if let Some(ref icon) = nip11.icon {
        html.push_str(&format!(
            r#"<tr><th>icon</th><td><a href="{}">{}</a></td></tr>"#,
            escape_html(icon),
            escape_html(icon)
        ));
        html.push('\n');
    }

    // GRASP-01 Extensions:
    // supported_grasps
    let grasps_str = nip11.supported_grasps.join(", ");
    html.push_str(&format!(
        r#"<tr><th>supported_grasps</th><td>{}</td></tr>"#,
        escape_html(&grasps_str)
    ));
    html.push('\n');

    // repo_acceptance_criteria
    html.push_str(&format!(
        r#"<tr><th>repo_acceptance_criteria</th><td>{}</td></tr>"#,
        escape_html(&nip11.repo_acceptance_criteria)
    ));
    html.push('\n');

    // curation (if present)
    if let Some(ref curation) = nip11.curation {
        html.push_str(&format!(
            r#"<tr><th>curation</th><td>{}</td></tr>"#,
            escape_html(curation)
        ));
        html.push('\n');
    }

    html
}

/// Generate the relay icon HTML for the header
fn generate_relay_icon_html(nip11: &RelayInformationDocument) -> String {
    match &nip11.icon {
        Some(icon_url) => format!(
            r#"<img src="{}" alt="Relay Icon" class="relay-icon">"#,
            escape_html(icon_url)
        ),
        None => String::new(),
    }
}

/// Generate the HTML landing page
pub fn get_html(config: &Config) -> String {
    // Get NIP-11 document for supported NIPs and GRASPs
    let nip11 = RelayInformationDocument::from_config(config);

    // Curation matches NIP-11 document
    let curation = nip11.curation.as_deref().unwrap_or("None").to_string();

    // Generate dynamic HTML for NIPs and GRASPs
    let hero_tags = generate_hero_tags(&nip11);
    let grasp_cards = generate_grasp_cards(&nip11);
    let nip_cards = generate_nip_cards(&nip11);
    let relay_info_rows = generate_relay_info_rows(&nip11);
    let relay_icon = generate_relay_icon_html(&nip11);

    format!(
        include_str!("../../templates/landing.html"),
        base_css = get_base_css(),
        relay_name = config.relay_name(),
        relay_description = config.relay_description,
        version = get_version(),
        nip11_version = escape_html(&nip11.version),
        curation = curation,
        repo_acceptance_criteria = escape_html(&nip11.repo_acceptance_criteria),
        theme_toggle = get_theme_toggle_html(),
        theme_script = get_theme_script(),
        hero_tags = hero_tags,
        grasp_cards = grasp_cards,
        nip_cards = nip_cards,
        relay_info_rows = relay_info_rows,
        relay_icon = relay_icon,
    )
}

/// Generate a generic 404 page for unknown paths
///
/// Used for any path that doesn't match a known route
pub fn get_generic_404_html(config: &Config, path: &str) -> String {
    let home_path = config.public_path("/");
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Not Found - {relay_name}</title>
    <style>
        {base_css}
        body {{
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .container {{ max-width: 480px; text-align: center; }}
        .error-code {{
            font-size: 6rem;
            font-weight: 700;
            color: var(--error);
            line-height: 1;
            margin-bottom: 8px;
        }}
        h2 {{ font-size: 1.5rem; font-weight: 500; margin-bottom: 16px; }}
        p {{ color: var(--text-muted); margin-bottom: 24px; }}
        .path-info {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 32px;
        }}
        .path-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        code {{ word-break: break-all; }}
        .footer {{ margin-top: 48px; }}
        .footer-separator {{ margin: 0 0.5em; opacity: 0.5; }}
    </style>
</head>
<body>
    {theme_toggle}
    <div class="container">
        <div class="error-code">404</div>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist.</p>
        <div class="path-info">
            <div class="path-label">Requested Path</div>
            <code>{path}</code>
        </div>
        <a href="{home_path}">&larr; Back to {relay_name}</a>
        <div class="footer"><span id="footer-domain"></span><span class="footer-separator">•</span>powered by <a href="https://gitworkshop.dev/danconwaydev.com/ngit-grasp"><strong>ngit-grasp</strong></a><span class="footer-separator">•</span>{version}<span class="footer-separator">•</span>MIT Licensed</div>
    </div>
    {footer_script}
    {theme_script}
</body>
</html>"##,
        base_css = get_base_css(),
        relay_name = config.relay_name(),
        home_path = escape_html(&home_path),
        path = path,
        version = get_version(),
        footer_script = get_footer_script(),
        theme_toggle = get_theme_toggle_html(),
        theme_script = get_theme_script(),
    )
}

/// Generate a 404 page for a non-existent repository
///
/// GRASP-01: "...and a 404 page for repositories it doesn't host"
pub fn get_404_html(config: &Config, npub: &str, identifier: &str) -> String {
    let home_path = config.public_path("/");
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Repository Not Found - {relay_name}</title>
    <style>
        {base_css}
        body {{
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .container {{ max-width: 480px; text-align: center; }}
        .error-code {{
            font-size: 6rem;
            font-weight: 700;
            color: var(--error);
            line-height: 1;
            margin-bottom: 8px;
        }}
        h2 {{ font-size: 1.5rem; font-weight: 500; margin-bottom: 16px; }}
        p {{ color: var(--text-muted); margin-bottom: 24px; }}
        .repo-info {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
            text-align: left;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
        }}
        .info-row + .info-row {{ border-top: 1px solid var(--border); }}
        .info-label {{ font-size: 0.875rem; color: var(--text-muted); }}
        code {{
            font-size: 0.75rem;
            word-break: break-all;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .hint {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 32px;
            font-size: 0.875rem;
            color: var(--text-muted);
        }}
        .footer {{ margin-top: 48px; }}
        .footer-separator {{ margin: 0 0.5em; opacity: 0.5; }}
    </style>
</head>
<body>
    {theme_toggle}
    <div class="container">
        <div class="error-code">404</div>
        <h2>Repository Not Found</h2>
        <p>This repository doesn't exist on this GRASP server.</p>
        <div class="repo-info">
            <div class="info-row">
                <span class="info-label">Owner</span>
                <code>{npub}</code>
            </div>
            <div class="info-row">
                <span class="info-label">Repository</span>
                <code>{identifier}</code>
            </div>
        </div>
        <div class="hint">The repository may not have been announced to this server, or the URL may be incorrect.</div>
        <a href="{home_path}">&larr; Back to {relay_name}</a>
        <div class="footer"><span id="footer-domain"></span><span class="footer-separator">•</span>powered by <a href="https://gitworkshop.dev/danconwaydev.com/ngit-grasp"><strong>ngit-grasp</strong></a><span class="footer-separator">•</span>{version}<span class="footer-separator">•</span>MIT Licensed</div>
    </div>
    {footer_script}
    {theme_script}
</body>
</html>"##,
        base_css = get_base_css(),
        relay_name = config.relay_name(),
        home_path = escape_html(&home_path),
        npub = npub,
        identifier = identifier,
        version = get_version(),
        footer_script = get_footer_script(),
        theme_toggle = get_theme_toggle_html(),
        theme_script = get_theme_script(),
    )
}

/// Generate a webpage for an existing repository
///
/// GRASP-01: "SHOULD serve a webpage at the same endpoint linking to git nostr client(s)
/// to browse the repository"
pub fn get_repo_html(config: &Config, npub: &str, identifier: &str) -> String {
    let home_path = config.public_path("/");
    let relay_path = serde_json::to_string(&home_path).expect("serialize configured base path");
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{identifier} - {relay_name}</title>
    <style>
        {base_css}
        .container {{ max-width: 720px; margin: 0 auto; padding: 60px 24px; }}
        .back-link {{ margin-bottom: 32px; }}
        .header {{ margin-bottom: 8px; }}
        h1 {{ font-size: 1.75rem; font-weight: 600; letter-spacing: -0.02em; }}
        .subtitle {{ color: var(--text-muted); }}
        .section {{ margin-bottom: 32px; }}
        .section-title {{
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text);
            margin-bottom: 12px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 20px;
        }}
        .card + .card {{ margin-top: 8px; }}
        code {{ font-size: 0.8rem; word-break: break-all; }}
        .clone-box {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 0.875rem;
            color: var(--text);
            overflow-x: auto;
        }}
        .clone-line {{ margin-bottom: 8px; }}
        .clone-line:last-child {{ margin-bottom: 0; }}
        .clone-box .cmd {{ color: var(--text-muted); }}
        .clone-box .url {{ color: var(--success); }}
        .browse-link {{
            display: inline-block;
            background: var(--brand);
            color: white;
            padding: 14px 24px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 1rem;
            margin: 32px 0;
            transition: background 0.2s;
            text-align: center;
        }}
        .browse-link:hover {{
            background: var(--brand-light);
            text-decoration: none;
        }}
        .browse-link .browse-identifier {{
            display: block;
            font-size: 1.125rem;
            font-weight: 600;
        }}
        .browse-link .browse-site {{
            display: block;
            font-size: 0.875rem;
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    {theme_toggle}
    <div class="container">
        <div class="back-link">
            <a href="{home_path}">&larr; {relay_name}</a>
        </div>
        <div class="header">
            <h1>{identifier}</h1>
            <h3 class="subtitle">by {npub}</h3>
        </div>
        <p class="subtitle">Git repository hosted using the <a href="https://ngit.dev/grasp">Grasp Protocol</a></p>
        
        <a id="gitworkshop-link" href="https://gitworkshop.dev" class="browse-link" target="_blank">
            <span class="browse-identifier">Browse Repository</span>
            <span class="browse-site">on GitWorkshop.dev &rarr;</span>
        </a>
        
        <div class="section">
            <div class="section-title">Clone</div>
            <div class="card">
                <div class="clone-box">
                    <div class="clone-line"><span class="cmd">curl -Ls https://ngit.dev/install.sh | bash</span></div>
                     <div class="clone-line"><span class="cmd">git clone</span> <span class="url" id="nostr-clone-url">nostr://{npub}/<span id="relayref"></span>/{encoded_identifier}</span></div>
                </div>
            </div>
        </div>
        <div class="footer"><span id="footer-domain"></span><span class="footer-separator">•</span>powered by <a href="https://gitworkshop.dev/danconwaydev.com/ngit-grasp"><strong>ngit-grasp</strong></a><span class="footer-separator">•</span>{version}<span class="footer-separator">•</span>MIT Licensed</div>
    </div>
    <script>
        // Detect protocol and construct relayref
        const protocol = window.location.protocol; // 'http:' or 'https:'
        const host = window.location.host; // 'domain.com' or 'domain.com:port'
        const relayPath = {relay_path};
        const websocketPath = relayPath === '/' ? '' : relayPath;
        
        // A path relay hint must carry the complete WebSocket URL. Root HTTPS
        // deployments retain the compact host-only relay hint.
        let relayref = host;
        if (protocol === 'http:' || websocketPath) {{
            const websocketProtocol = protocol === 'http:' ? 'ws://' : 'wss://';
            relayref = encodeURIComponent(websocketProtocol + host + websocketPath);
        }}
        
        // Update the relayref in the clone URL
        document.getElementById('relayref').textContent = relayref;
        
        // Construct gitworkshop link: gitworkshop.dev/npub/relayref/identifier
        const gitworkshopLink = document.getElementById('gitworkshop-link');
        gitworkshopLink.setAttribute('href', 'https://gitworkshop.dev/{npub}/' + relayref + '/{encoded_identifier}');
        
        // Set footer domain
        var footerDomain = document.getElementById('footer-domain');
        if (footerDomain) {{
            footerDomain.textContent = host;
        }}
    </script>
    {theme_script}
</body>
</html>"##,
        base_css = get_base_css(),
        relay_name = config.relay_name(),
        home_path = escape_html(&home_path),
        relay_path = relay_path,
        npub = npub,
        identifier = identifier,
        encoded_identifier = percent_encode(identifier),
        version = get_version(),
        theme_toggle = get_theme_toggle_html(),
        theme_script = get_theme_script(),
    )
}
