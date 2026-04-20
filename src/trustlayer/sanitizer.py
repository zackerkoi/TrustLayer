from __future__ import annotations

from html.parser import HTMLParser


class VisibleTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_depth = 0
        self.script_style_depth = 0
        self.removed_regions: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        style = attrs_dict.get("style", "").replace(" ", "").lower()
        is_hidden = (
            "hidden" in attrs_dict
            or "display:none" in style
            or "visibility:hidden" in style
        )

        if tag.lower() in {"script", "style"}:
            self.script_style_depth += 1
            self.removed_regions.add(tag.lower())
            return

        if is_hidden:
            self.hidden_depth += 1
            self.removed_regions.add("hidden_element")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self.script_style_depth > 0:
            self.script_style_depth -= 1
            return

        if self.hidden_depth > 0:
            self.hidden_depth -= 1

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.removed_regions.add("html_comment")

    def handle_data(self, data: str) -> None:
        if self.hidden_depth > 0 or self.script_style_depth > 0:
            return
        cleaned = " ".join(data.split())
        if cleaned:
            self.parts.append(cleaned)

    def extract(self, html: str) -> tuple[str, list[str]]:
        self.feed(html)
        return "\n".join(self.parts), sorted(self.removed_regions)
