"""Keep published terminology, linked examples and the native format consistent."""

from html.parser import HTMLParser
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from sail import __version__, commands

ROOT = Path(__file__).resolve().parents[2]


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.links = []
        self.handlers = []
        self.lang = None
        self.canonical_urls = []
        self.social_urls = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.lang = attrs.get("lang")
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical_urls.append(attrs.get("href"))
        if tag == "meta" and attrs.get("property") == "og:url":
            self.social_urls.append(attrs.get("content"))
        self.handlers.extend(name for name in attrs if name.startswith("on"))


def test_public_sources_follow_english_brand_and_character_constraints():
    assert (ROOT / "sail/LICENSE.md").read_bytes() == (ROOT / "SAIL-GPL-1.0.md").read_bytes()
    files = [ROOT / "README.md", ROOT / "SAIL-GPL-1.0.md", ROOT / "SECURITY.md",
             ROOT / "web/index.html", ROOT / "sail/README.md", ROOT / "sail/examples/README.md"]
    files += list((ROOT / "docs").glob("*.md"))
    files += list((ROOT / "sail/src/sail").glob("*.py"))
    for path in files:
        if path.name.startswith("._"):
            continue
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text and "\u00a7" not in text, path
    for path in (ROOT / "README.md", ROOT / "SAIL-GPL-1.0.md", ROOT / "web/index.html"):
        text = path.read_text(encoding="utf-8")
        assert "Secure Super AI General Public License" in text
        assert "SAI" in text
        assert "OMS-compatible" not in text
        assert "COMPLIANT" not in text


def test_website_has_valid_accessible_navigation_and_version_markers():
    text = (ROOT / "web/index.html").read_text(encoding="utf-8")
    page = Page()
    page.feed(text)
    assert page.lang == "en"
    assert len(page.ids) == len(set(page.ids))
    assert not page.handlers
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))
    assert "prefers-reduced-motion" in text
    assert "aria-live" in text
    assert 'data-tier="T3"' in text
    assert "blob/main/SAIL-GPL-1.0.md" in text
    assert "blob/main/docs/SRM-FORMAT.md" in text
    assert __version__.rsplit(".", 1)[0] in text
    assert re.search(r"VERIFIED.*technical", text)


def test_committed_example_is_verified_with_its_separate_test_trust_anchor():
    rep = commands.verify(ROOT / "example-model", trusted_key=ROOT / "sail/examples/example-public-key.json")
    assert rep.ok, rep.checks
    assert rep.identity_verified


def test_public_site_uses_consistent_canonical_domain():
    canonical = "https://sail-gpl.org/"
    page = Page()
    page.feed((ROOT / "web/index.html").read_text(encoding="utf-8"))
    assert page.canonical_urls == [canonical]
    assert page.social_urls == [canonical]
    robots = (ROOT / "web/robots.txt").read_text(encoding="utf-8")
    sitemap_lines = [line for line in robots.splitlines() if line.startswith("Sitemap:")]
    assert sitemap_lines == [f"Sitemap: {canonical}sitemap.xml"]
    sitemap = ET.parse(ROOT / "web/sitemap.xml")
    locations = sitemap.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
    assert [location.text for location in locations] == [canonical]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"[sail-gpl.org]({canonical})" in readme
    assert "Vercel hosts the static presentation site" in readme
