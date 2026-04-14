package main

# Roles are namespace-scoped resources. A Role without a namespace will be
# silently defaulted by the API server, which can result in permissions being
# granted in an unintended namespace. Require every Role to declare its
# namespace explicitly so intent is clear.
deny contains msg if {
  input.kind == "Role"
  not input.metadata.namespace
  msg := sprintf("Role %v must have a namespace set", [input.metadata.name])
}

deny contains msg if {
  input.kind == "RoleBinding"
  not input.metadata.namespace
  msg := sprintf("RoleBinding %v must have a namespace set", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"
}