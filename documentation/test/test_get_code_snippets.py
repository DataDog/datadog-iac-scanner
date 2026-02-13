import pytest
from unittest.mock import patch
from pathlib import Path

from local_gen import get_code_snippets


class TestGetCodeSnippets:
    @pytest.fixture
    def fake_test_dir(self):
        return Path("/fake/test/dir")

    @patch("local_gen.read_file_contents")
    @patch("local_gen.glob.iglob")
    def test_get_code_snippets(self, mock_iglob, mock_read, fake_test_dir):

        mock_files_neg = [fake_test_dir / "negative1.tf", fake_test_dir / "negative2.tf"]
        mock_files_pos = [fake_test_dir / "positive1.tf"]

        def iglob_side_effect(pattern):
            if "negative" in pattern:
                return mock_files_neg
            if "positive" in pattern:
                return mock_files_pos
            return []

        mock_iglob.side_effect = iglob_side_effect
        mock_read.return_value = 'resource "aws_s3_bucket" "example" {}'

        compliant, non_compliant = get_code_snippets(fake_test_dir, "hcl", max_examples=2)

        expected_snippet = '```hcl\nresource "aws_s3_bucket" "example" {}\n```'
        assert compliant == [expected_snippet, expected_snippet]
        assert non_compliant == [expected_snippet]
        assert mock_read.call_count == 3
