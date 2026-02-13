import pytest
import local_gen
from unittest.mock import patch
from pathlib import Path


class TestBuildMarkdown:

    @pytest.fixture
    def test_rule_path(self):
        return Path("/test")

    @pytest.fixture
    def test_string(self):
        return "test"

    @pytest.fixture
    def test_metadata(self):
        return {
            "queryName": "mockQueryName",
            "id": "mockId",
            "platform": "mockPlatform",
            "severity": "mockSeverity",
            "category": "mockCategory",
            "descriptionText": "mockDescriptionText",
            "descriptionUrl": "mockDescriptionUrl"
        }

    @pytest.fixture
    def test_code_snippets(self):
        return "compliant", "non-compliant"

    def test_success(self, test_metadata, test_rule_path, test_string, test_code_snippets):
        with patch("local_gen.get_code_snippets", return_value=test_code_snippets) as mock_snippets:
            markdown = local_gen.build_markdown(test_rule_path, test_metadata, test_string, test_string, 0)
            for key, value in test_metadata.items():
                if key != "severity":
                    assert markdown.find(value) > 0
                else:
                    assert markdown.find(value.upper()) > 0
            mock_snippets.assert_called_once()
