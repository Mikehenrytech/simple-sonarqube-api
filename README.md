# simple-sonarqube-api
Sonarqube api python module


# Usage

## Example

Install module
```bash
$ pip install simple-sonarqube-api
```

Code example
```python
from simple_sonarqube_api.client import SonarQubeClient

client = SonarQubeClient(
    base_url="https://sonar.midominio",
    token="squ_xxxxxxxxx"
)

assert client.is_authenticated()

issues = list(client.iter_issues(types="VULNERABILITY", resolved=False))
evidence = client.get_issue_code_evidence(issues[0]["key"], context_lines=3)

print(evidence["snippet"])
```