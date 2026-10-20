# SPDX-FileCopyrightText: 2026 The weft authors
# SPDX-License-Identifier: MIT
"""StrictDoc configuration: requirements in requirements/, traced to src/ and tests/."""

from strictdoc.core.project_config import ProjectConfig


def create_config() -> ProjectConfig:
    return ProjectConfig(
        project_title="weft-agent requirements",
        project_features=[
            "REQUIREMENT_TO_SOURCE_TRACEABILITY",
            "TRACEABILITY_MATRIX_SCREEN",
        ],
        include_doc_paths=["requirements/**"],
        source_root_path=".",
        include_source_paths=["crates/**"],
        exclude_source_paths=["**/target/**"],
    )
