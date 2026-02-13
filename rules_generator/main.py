import argparse
from pathlib import Path

from classes.CodeProcessor import CodeProcessor
from classes.RulesGenerator import RulesGenerator
from classes.JsonlGenerator import JsonlGenerator
from classes.Coordinator import Coordinator


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate module support and terraform examples from existing rules"
    )
    parser.add_argument("generation", type=str, help="Which function to call")
    parser.add_argument("--path", type=str, default="", help="Path")
    parser.add_argument(
        "--skip", type=int, default=0, help="Number of rules to skip in generation"
    )
    parser.add_argument(
        "--check-sev",
        type=bool,
        default=True,
        help="Triggers the rule generation only for the rules with Critical and High severity",
    )
    return parser.parse_args()


def get_new_rule(path: str) -> str:
    """Generate a single new rule from a specified path where the query.rego can be found."""
    rulesGenerator = RulesGenerator()
    codeProcessor = CodeProcessor()

    snippet = codeProcessor.read_snippet(path)
    new_rule = rulesGenerator.send_rule_request(snippet)

    return new_rule


def write_rules_generation_llm_jsonl(path: str = "module_support"):
    """Write the fine-tuning jsonl for the llm in charge of generating the rule.

    The path is leading to a folder where the rules do not have the module support.
    Use the bash_scripts to create this folder by copying the ones in the assets.

    After the folder generation, you have to remove the module support manually.
    Also, in the assets folder, all the queries must be appended with @@@@@ and then a mapping like the following:
    {
        "source": {
            "resource": {
                "resources": [...],
                "inputs": {
                    ...
                }
            }
        }
    }"""
    jsonlGenerator = JsonlGenerator(path)
    return jsonlGenerator.write_module_jsonl()


def write_terraforms_generation_llm_jsonl():
    """Write the fine-tuning jsonl for the llm in charge of generating the terraforms.

    The path is leading to a folder where the rules have the module support and also examples of terraforms using the modules.
    Use the bash_scripts to create this folder by copying the ones in the assets.

    After the folder generation, you have to append @@@@@ to the rules and a mapping like the following:
    {
        "source": {
            "resource": {
                "resources": [...],
                "inputs": {
                    ...
                }
            }
        }
    }"""
    jsonlGenerator = JsonlGenerator("module_support")
    return jsonlGenerator.write_terraform_jsonl()


def generate_module_support(path: str, skip: int = 0, check_sev: bool = True) -> None:
    """Generate all the module support for the rego rules.
    path is basically assets/queries/terraform/aws"""
    coordinator = Coordinator()
    coordinator.generate_module_support(path, skip, check_sev)


def generate_metadata(path: str) -> None:
    coordinator = Coordinator()
    coordinator.generate_metadata(path)


def extend_descriptions(path: str) -> None:
    coordinator = Coordinator()
    coordinator.generate_extended_descriptions(path)


if __name__ == "__main__":
    args = parse_args()
    asked = args.generation
    path = args.path
    skip = args.skip
    check_sev = args.check_sev
    if asked == "get_new_rule":
        print(get_new_rule(path))
    elif asked == "write_rules_generation_llm_jsonl":
        print(write_rules_generation_llm_jsonl())
    elif asked == "write_definitive_terraforms_jsonl":
        print(write_terraforms_generation_llm_jsonl())
    elif asked == "generate_module_support":
        generate_module_support(path, skip, check_sev)
    elif asked == "generate_metadata":
        generate_metadata(path)
    elif asked == "extend_descriptions":
        extend_descriptions(path)
