![Tests](https://github.com/alexott/databricks-sigma-backend/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexott/GitHub Gist identifier containing coverage badge JSON expected by shields.io./raw/alexott-databricks-sigma-backend.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma databricks Backend

This is the databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
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
 
