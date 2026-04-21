package main

# ServiceAccounts are namespace-scoped resources. A ServiceAccount without a namespace will be
# silently defaulted by the API server, which can result in permissions being
# granted in an unintended namespace. Require every ServiceAccount to declare its
# namespace explicitly so intent is clear.
deny contains msg if {
  input.kind == "ServiceAccount"
  not input.metadata.namespace
  msg := sprintf("ServiceAccount %v must have a namespace set", [input.metadata.name])
}