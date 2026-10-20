# Real Policy API responses

`scuba_policy_response_*.json` are test fixtures from CISA's ScubaGoggles
(<https://github.com/cisagov/ScubaGoggles>, `scubagoggles/Testing/Unit/Python/data/policyapi_get_policies*.json`, released under CC0).
Each holds real Cloud Identity Policy API pages (`responses`), the organisational units and groups they refer to, and the **expected
reduced result** (`results`). `tests_python/workspace/test_policy_oracle.py` runs our reducer on the responses and checks it reproduces
the expected result, which is an independent check that does not depend on our own reading of the API's rules.
