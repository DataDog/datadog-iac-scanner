from openai import OpenAI
from classes.models.Output import QueryAndDescriptionOutput, DescriptionOutput


class RulesGenerator:

    def __init__(self):
        self.client = OpenAI()

    def send_rule_request(self, code_snippet: str) -> str:
        system_message = """You're an expert writing Rego and also in Terraform and its module support. When provided with a Rego file about a Terraform infrastructure add support for the modules.
Know that the rego get_module_equivalent_key function takes 4 arguments which are the provider of the module, the source of the module, the resource and the key to look for. Also, be careful of nested attributes, separate the tests to get the key first and the the nested attribute.
Answer with only the refactored code, one new line, "@@@@@", a second new line and a json with the source of the module as a key holding two attributes, resources which is a list of the supported resources and inputs which holds the mapping between the module variable and the resource variable."""
        response = self.client.responses.create(
            model="ft:gpt-4.1-2025-04-14:datadog-staging:module-support:BzKPAmRd",
            input=[
                {"role": "system", "content": system_message},
                {"role": "developer", "content": code_snippet},
            ],
        )
        return response.output_text

    def send_terraform_request(self, code_snippet: str) -> str:
        system_message = """You're an expert writing Rego and also in Terraform and its module support.
        The User will provide you with a module source, one or multiple terraform resources and a rego file. Your job is to emit terraform code examples.
    Answer with a positive example that will trigger the rule, one new line, "@@@@@", a second new line and a negative example that won't trigger the rule."""
        response = self.client.responses.create(
            model="ft:gpt-4.1-2025-04-14:datadog-staging:terraform-examples:BzIuIlyu",
            input=[
                {"role": "system", "content": system_message},
                {"role": "developer", "content": code_snippet},
            ],
        )
        return response.output_text

    def send_rule_doc_formatting_request(
        self, metadata: dict
    ) -> QueryAndDescriptionOutput:
        system_message = """You are to format some text. You will be provided with a rule name, line break, @@@@@, line break and a rule description.
Your job is to ensure that the case of the rule's name is good: except the first word, proper nouns and acronyms, no word should start with a capital case.
Your job is to reformulate the description to make it as clear as possible. Use the following rules to do so:
Task:
- Improve the wording for clarity and grammar.
- Do not change the technical meaning.
- Stay as close to the original phrasing as possible (minimal edits).
- Normalize tone (declarative, consistent).
- Correct grammar, articles, and awkward phrasing (e.g., "should not have" → "should not include", "defined and set to" → "set to").
- Keep flags and component names accurate, wrap CLI flags in backticks.
- Do not rewrite into instructions — preserve the original contextual style.
- Extend the rule's description using your understanding the rego rule - two to three lines.
- Put all the attributes as code snippets"""

        queryName = metadata["queryName"]
        descriptionText = metadata["descriptionText"]
        response = self.client.responses.parse(
            model="gpt-5-mini-2025-08-07",
            input=[
                {"role": "system", "content": system_message},
                {
                    "role": "user",
                    "content": f"queryName: {queryName}\n\descriptionText: {descriptionText}",
                },
            ],
            text_format=QueryAndDescriptionOutput,
        )
        return response.output_parsed

    def send_rule_doc_extend_description_request(
        self, rule: str, metadata: dict
    ) -> DescriptionOutput:
        system_message = """You are a cloud security engineer writing descriptions for Infrastructure-as-Code security rules.

Your goal: Create clear, balanced descriptions that explain both the SECURITY IMPACT and the TECHNICAL REQUIREMENTS.

REQUIREMENTS:

1. SECURITY CONTEXT FIRST (Always start here)
   - Begin with what the misconfiguration is and why it matters for security
   - Keep sentences clear and concise - avoid run-on sentences that list multiple risks in one breath

2. TECHNICAL DETAILS SECOND (Be specific and helpful)
   - Specify which resource type and property to check
   - You MAY include implementation details if they help users fix issues:
     ✅ "Resources missing this property will be flagged"
     ✅ "If set to false, this indicates..."
     ✅ "The property must be defined and set to..."
   - Be precise about property names and expected values
   - Keep paths concise (don't over-explain nested structures)

3. STRUCTURE (Adapt based on rule complexity):
   - Simple/Informational rules (e.g., inventory): 2-3 concise sentences, focus on what and why
   - Standard security rules: 3-4 sentences covering requirement, risk, configuration, and implementation
   - Complex rules: Add code examples when configuration is not obvious from property name alone
   - AVOID REPETITION: Do not restate the same security risk using different words. Combine related security concepts into a single clear statement.

   Core elements:
   - Sentence 1: What should be configured + why it matters (1-2 reasons max)
   - Sentence 2: Technical specifics - which resource type, property, and expected value
   - Optional Sentence 3: Implementation details or edge cases
   - Optional Sentence 4: Additional technical context if needed

   Keep each sentence focused on ONE idea. Break up complex thoughts into multiple clear sentences.

4. CODE EXAMPLES (Optional but recommended):
   - Where possible, show ONLY the secure configuration in code snippets using backticks
   - Do NOT reference configurations unless you show the actual code
   - If you show code blocks, include a newline before and after the block
   - If you show an example, ALWAYS show at least a secure example (don't just show insecure)
   - Use the appropriate format for the platform (CloudFormation YAML/JSON, Terraform HCL, etc.)

5. FORMATTING REQUIREMENTS:
   - Write descriptions as a continuous paragraph or well-structured text
   - Do NOT insert random line breaks in the middle of sentences
   - Use proper paragraph breaks only between distinct sections (e.g., between prose and code examples)
   - Do NOT add "Rule ID:" yourself - it will be automatically appended after your description
   - Focus on writing the description content only

6. BALANCED EXAMPLES:

   ✅ EXCELLENT (Security + Implementation):
   "RDS database instances must have storage encryption enabled to protect data at rest from unauthorized access. Without encryption, sensitive data in database volumes, snapshots, and backups remains vulnerable to exposure if storage media is compromised. The `StorageEncrypted` property in `AWS::RDS::DBInstance` resources must be set to `true`. Resources missing this property or with StorageEncrypted=false will be flagged."

   ✅ EXCELLENT (Security + Technical Precision):
   "Lambda function permissions should not grant access to wildcard principals ('*'), as this creates unintended public access and exposes function invocations to any AWS account or unauthenticated users. The `Principal` property in `AWS::Lambda::Permission` resources must specify explicit principals such as AWS account IDs, service principals, or ARNs. Resources with Principal='*' will be flagged as a security risk."

   ✅ EXCELLENT (Security + Configuration Details):
   "Security Groups should not allow SSH access (port 22) from the public internet (0.0.0.0/0), as this exposes instances to brute force attacks, credential stuffing, and unauthorized access attempts. Restrict SSH ingress rules to specific trusted IP ranges or use bastion hosts. This rule flags SecurityGroupIngress entries with CidrIp=0.0.0.0/0 and port 22 exposed."

   ✅ EXCELLENT (With Code Examples):
   "S3 buckets must have server-side encryption enabled to protect data at rest from unauthorized access. Without encryption, sensitive data stored in S3 is vulnerable to exposure if the bucket is misconfigured or compromised.

   Secure configuration with encryption enabled:

   ```yaml
   MyBucket:
     Type: AWS::S3::Bucket
     Properties:
       BucketName: my-bucket
       BucketEncryption:
         ServerSideEncryptionConfiguration:
           - ServerSideEncryptionByDefault:
               SSEAlgorithm: AES256
   ```"

7. EXAMPLES TO AVOID:

   ❌ BAD (Implementation only, no security context):
   "The rule checks if Properties.Encrypted is false and reports an IncorrectValue with the expected and actual values."
   → Missing: WHY encryption matters for security

   ❌ BAD (Too brief, no detail):
   "EFS must have the Encrypted property set to true."
   → Missing: Security impact AND technical specifics

   ❌ BAD (Over-technical, lost the message):
   "Resources.<resourceName>.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm must be defined."
   → Too verbose about paths, missing security context

   ❌ BAD (run-on sentence):
   "Enabling API Gateway cache clustering for Serverless APIs reduces backend load and improves availability, because when caching is disabled every request is forwarded to backend services—raising the risk of resource exhaustion, higher latency, and amplification of brute-force or denial-of-service patterns that can lead to service disruption or data exposure."
   → Problems: (1) Run-on sentence cramming too many ideas, (3) technical requirement is buried

8. TONE:
   - Professional and declarative
   - Security-focused but technically precise
   - Actionable for developers fixing issues
   - No marketing fluff or excessive fear-mongering

Using the Rego rule provided for context, analyze what security issue it's checking for and write a balanced description that starts with security impact and includes helpful technical details.

Output only the improved description text, no preamble."""

        descriptionText = metadata["descriptionText"]
        response = self.client.responses.create(
            model="gpt-5-mini-2025-08-07",
            input=[
                {"role": "system", "content": system_message},
                {
                    "role": "user",
                    "content": f"rule: {rule}\ndescriptionText: {descriptionText}",
                },
            ],
        )
        return response.output_text
