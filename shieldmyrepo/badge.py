"""
Badge SVG generator.

Generates a shields.io-style SVG badge showing the security grade
that can be embedded in READMEs.
"""

import os


BADGE_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="ShieldMyRepo: {grade}">
  <title>ShieldMyRepo: {grade}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="93" height="20" fill="#555"/>
    <rect x="93" width="{right_width}" height="20" fill="{color}"/>
    <rect width="{width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="475" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">ShieldMyRepo</text>
    <text x="475" y="140" transform="scale(.1)" fill="#fff">ShieldMyRepo</text>
    <text aria-hidden="true" x="{text_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{label}</text>
    <text x="{text_x}" y="140" transform="scale(.1)" fill="#fff">{label}</text>
  </g>
</svg>"""


GRADE_CONFIGS = {
    "A": {"color": "#4c1", "label": "A — Excellent"},
    "B": {"color": "#97ca00", "label": "B — Good"},
    "C": {"color": "#dfb317", "label": "C — Fair"},
    "D": {"color": "#fe7d37", "label": "D — Poor"},
    "F": {"color": "#e05d44", "label": "F — Critical"},
}


def generate_badge(grade: str, output_dir: str) -> str:
    """Generate an SVG badge for the security grade.

    Args:
        grade: Letter grade (A-F).
        output_dir: Directory to save the badge SVG.

    Returns:
        Path to the generated badge SVG file.
    """
    config = GRADE_CONFIGS.get(grade, GRADE_CONFIGS["F"])
    label = config["label"]
    color = config["color"]

    # Calculate widths
    right_width = len(label) * 7 + 10
    width = 93 + right_width
    text_x = (93 + width) * 5  # center of right section, scaled

    svg = BADGE_TEMPLATE.format(
        width=width,
        right_width=right_width,
        color=color,
        grade=grade,
        label=label,
        text_x=text_x,
    )

    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "shieldmyrepo-badge.svg")
    with open(filepath, "w") as f:
        f.write(svg)

    return filepath
