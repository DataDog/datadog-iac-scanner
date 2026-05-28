import json
from typing import List, Dict
from pathlib import Path


class JsonlGenerator:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        """prefix is used with folder where the rules/terraforms with module support is"""

    def __write_json(
        self, user_message: str, assistant_message: str, system_message: str
    ) -> str:
        json_string = {
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": assistant_message},
            ]
        }

        return json.dumps(json_string)

    def __write_jsonl_from_couples(
        self, couples: List[Dict[str, str]], key1: str, key2: str, system_message: str
    ) -> str:
        s = ""
        for couple in couples:
            s += self.__write_json(couple[key1], couple[key2], system_message) + "\n"
        return s

    def __create_no_module_and_module_structure(self) -> List[Dict[str, str]]:
        snippets = []
        standard_path = Path(self.prefix) / "queries/terraform/aws/"
        if not (standard_path.is_dir()):
            return snippets
        for rule_path in (standard_path).iterdir():
            try:
                with (
                    open(rule_path / "query.rego", "r") as f_no_modules,
                    open(
                        (rule_path / "query.rego")
                        .absolute()
                        .as_posix()
                        .replace(self.prefix, "assets"),
                        "r",
                    ) as f_modules,
                ):
                    snippets.append(
                        {"no_modules": f_no_modules.read(), "modules": f_modules.read()}
                    )
            except Exception as e:
                print(e)
        return snippets

    def __create_snippet_and_terraforms_structure(self) -> List[Dict[str, str]]:
        couples = []
        standard_path = Path(self.prefix) / "queries/terraform/aws"
        if not (standard_path.is_dir()):
            return couples
        for rule_path in (standard_path).iterdir():
            test_path = rule_path / "test"
            query_path = rule_path / "query.rego"
            if not (test_path.is_dir() and query_path.is_file()):
                continue
            positive_path = ""
            negative_path = ""
            for test in test_path.iterdir():
                if "positive" in test.name:
                    positive_path = test
                elif "negative" in test.name:
                    negative_path = test
            if positive_path == "" or negative_path == "":
                continue
            with (
                open(positive_path, "r") as f_positive,
                open(negative_path, "r") as f_negative,
                open(query_path, "r") as f_rule,
            ):
                couples.append(
                    {
                        "rule": f_rule.read(),
                        "terraforms": f"{f_positive.read()}\n#####\n{f_negative.read()}",
                    }
                )
        return couples

    def write_module_jsonl(self) -> str:
        system_message = """You're an expert writing Rego and also in Terraform and its module support. When provided with a Rego file about a Terraform infrastructure add support for the modules.
Know that the rego get_module_equivalent_key function takes 4 arguments which are the provider of the module, the source of the module, the resource and the key to look for. Also, be careful of nested attributes, separate the tests to get the key first and the the nested attribute.
Answer with only the refactored code, one new line, "@@@@@", a second new line and a json with the source of the module as a key holding two attributes, resources which is a list of the supported resources and inputs which holds the mapping between the module variable and the resource variable."""
        return self.__write_jsonl_from_couples(
            self.__create_no_module_and_module_structure(),
            "no_modules",
            "modules",
            system_message,
        )

    def write_terraform_jsonl(self) -> str:
        system_message = """You're an expert writing Rego and also in Terraform and its module support. 
The User will provide you with a rego file and one or multiple sources and their resources associated withe the rule. Your job is to emit terraform code examples.
Answer with a positive example that will trigger the rule, one new line, "@@@@@", a second new line and a negative example that won't trigger the rule."""
        return self.__write_jsonl_from_couples(
            self.__create_snippet_and_terraforms_structure(),
            "rule",
            "terraforms",
            system_message,
        )
