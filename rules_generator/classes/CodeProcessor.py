import json
from pathlib import Path
from typing import Optional, Any


class CodeProcessor:
    def __read_file(self, path: Path) -> str:
        try:
            with open(path, "r") as f:
                return f.read()
        except Exception as e:
            print(e)

    def read_snippet(self, path: Path) -> str:
        return self.__read_file(path / "query.rego")

    def read_metadata(self, path: Path) -> str:
        return self.__read_file(path / "metadata.json")

    def load_metadata(self, path: Path) -> dict:
        try:
            with open(path / "metadata.json", "r") as f:
                metadata = json.load(f)
            return metadata
        except Exception as e:
            print(e)

    def __write_file(self, path: Path, content: str) -> None:
        try:
            with open(path, "w") as f:
                f.write(content)
        except Exception as e:
            print(e)

    def load_common(self) -> Any:
        raise NotImplementedError("common.json has been removed; library content is now managed in the default-rules repository")

    def update_common(self, common: Any, update: Any) -> Any:
        raise NotImplementedError("common.json has been removed; library content is now managed in the default-rules repository")

    def write_common(self, common: Any) -> None:
        raise NotImplementedError("common.json has been removed; library content is now managed in the default-rules repository")

    def write_rule_snippet(self, path: Path, snippet: str) -> Optional[Any]:
        splitAt = snippet.split("@@@@@")
        parts = splitAt if len(splitAt) > 1 else snippet.split("#####")
        if len(parts) > 1:
            update = {"common_lib": {"modules": {"aws": {}}}}
            try:
                update["common_lib"]["modules"]["aws"] = json.loads(parts[1])
                self.__write_file(path / "query.rego", parts[0])
                return update
            except Exception as e:
                print(f"Failed to generate json module mapping for {path}: {e}")
                return {}

    def write_terraform_snippets(self, path: Path, snippets: str) -> None:
        splitAt = snippets.split("@@@@@")
        snippets_list = splitAt if len(splitAt) > 1 else snippets.split("#####")
        self.__write_file(path / "test/positive_module.tf", snippets_list[0].strip())
        self.__write_file(path / "test/negative_module.tf", snippets_list[1].strip())

    def write_metadata(self, path: Path, metadata: dict) -> None:
        with open(path / "metadata.json", "w") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
