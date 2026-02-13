# Rules generation

## Preemptive warning

I would recommed running all those scripts from the root of the repo. No other way has been tested yet, so this might save you a lot of time and of troubleshooting.

## Introduction

The goal of those scripts is to generate the Rego rules that we need for the module support. This task is split in two: fine tunes the LLMs, ask them to generate the rules and tests for real. There are a few files to use for those tasks.

## Fine-tuning

### How does fine-tuning work with OpenAI

Fine tuning with OpenAI requires only one file: a jsonl file where each line is a valid json containing an example of a whole conversation data:

```json
{"messages":[{"role": "user", "content": "Tell me why"}, {"role": "assistant", "content": "Ain't nothing but a heartache"}]}
```
The json contains a `messages` attribute which holds an array with all the messages. Each message is an object with two variables: `role` and `content`. `role` can be one of three things:
- system: a message designed to customize globally the behavior of the LLM.
- user: simulates a message that a user would send.
- assistant: a correct expected answer from the LLM.
For the fine-tuning to work, 50 to 100 conversations are recommended.

### Run the scripts to generate the jsonl files for the fine-tuning
To have the best results, I decided to use two seperate models, each one fine-tuned specifically for its own task. 
Those task are very long because a lot of work has to be achieved manually. If we decide to use this later on, the best option would be to automate it the best we can.

#### Rule generation

To generate the jsonl for the Rule generation, the principle is the same: we grab the already existing examples of rules supporting modules and put them inside a directory. This can be achieved using the `copy_module_supporting_rules.bash` script or soon enough, the `rules-generation-fine-tuning.bash` script. Then you remove the module support from those files which will be used as prompt example for the llm and the ones in the `assets/query` folder will be used as response example. Also, in the `assets/query` folder, all the queries must be appended with @@@@@ and then a mapping like the following:
```json
{
    "source": {
        "resource": {
            "resources": [...],
            "inputs": {
                ...
            }
        }
    }
}
```
Then you launch the python script that will go through those files and generate a jsonl from them:

```bash
python3 rules_generator/main.py write_definitive_module_jsonl
```
This will output a jsonl that you can put into a file redirecting the output.

#### Terraform generation

To generate the jsonl for the Terraform generation: we grab both the existing rules supporting modules and also the according terraform files. This can be achieved using the `copy_module_supporting_rules.bash` and then the `copy_module_supporting_terraforms.bash` scripts and soon enough, only using the `terraforn-generation-fine-tuning.bash` script. After the folder generation, you have to append @@@@@ to the rules and a mapping like the following:
```json
{
    "source": {
        "resource": {
            "resources": [...],
            "inputs": {
                ...
            }
        }
    }
}
```
Then you launch the python script that will go through those files and generate a jsonl from them:

```bash
python3 rules_generator/main.py write_definitive_terraforms_jsonl
```
This will output a jsonl that you can put into a file redirecting the output.

#### Warning about the jsonl files

Do not let any blank line. Those lines are also checked and may invalidate the file.

### Run a fine-tuning job

Go to the [fine-tuning](https://platform.openai.com/finetune/) dashboard of the OpenAI platform. There you will find a create button that will prompt you most importantly for a model and a jsonl file. In my attempts, I used the `gpt-4.1-2025-04-14`.

## Generate the rules

The rules are all sent to the LLMs API and we get from them both the new rules and also the terraform examples. To run the rules generation, just run:

```bash
python3 rules_generator/main.py generate_module_support --path assets/queries/terraform/aws
```
