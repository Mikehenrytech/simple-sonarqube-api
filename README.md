# simple-sonarqube-api
Sonarqube api python module


# Usage

# Build module

```bash
python -m venv .venv

```
## Linux/macOS
```bash
source .venv/bin/activate
```

## Windows (PowerShell)
```bash
# .\.venv\Scripts\Activate.ps1
```

## build
```bash
python -m pip install -U pip
pip install -e .
```


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

## Check bandit
```bash
$ bandit -r src/simple_sonarqube_api
```