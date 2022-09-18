![Tests](https://github.com/alexott/databricks-sigma-backend/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexott/GitHub Gist identifier containing coverage badge JSON expected by shields.io./raw/alexott-databricks-sigma-backend.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

Status: **experimental**, work in progress:

* Although `cidrmatch` is generated, you still need to provide corresponding function as UDF (I'll add example later)
* Keywords (text rules without specific field) aren't supported yet
* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* pipeline1: purpose
* pipeline2: purpose

It supports the following output formats:

* default: plain Databricks/Apacha Spark SQL queries
* detection_yaml: Yaml markup for my own small detection framework

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)


## TODOs

 - Try to rewrite expressions like `foo*bar` into `(startswith(field, "foo") and endswith(field, "bar"))`
 
 - Fix error when processing following files: `sigma/rules/proxy/proxy_empty_ua.yml` & `sigma/rules/cloud/azure/azure_ad_sign_ins_from_unknown_devices.yml` & `sigma/rules/windows/registry/registry_set/registry_set_disable_winevt_logging.yml`
 
 ```
   File "lib/python3.8/site-packages/sigma/conversion/base.py", line 106, in <listcomp>
    self.convert_condition(cond.parsed, state)
  File "lib/python3.8/site-packages/sigma/conversion/base.py", line 324, in convert_condition
    return self.convert_condition_field_eq_val(cond, state)
  File "lib/python3.8/site-packages/sigma/conversion/base.py", line 245, in convert_condition_field_eq_val
    return self.convert_condition_field_eq_val_str(cond, state)
  File "lib/python3.8/site-packages/sigma/conversion/base.py", line 632, in convert_condition_field_eq_val_str
    and cond.value.endswith(SpecialChars.WILDCARD_MULTI)            # String ends with wildcard
  File "lib/python3.8/site-packages/sigma/types.py", line 329, in endswith
    c = self.s[-1]
```
